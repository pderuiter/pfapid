// Package api is the unprivileged HTTPS front end. It authenticates clients
// by certificate (mTLS, TLS 1.3 only), authorises each request against the
// client's scope, and forwards it to the privileged side. It never touches
// pf itself.
package api

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pderuiter/pfapid/internal/model"
	"github.com/pderuiter/pfapid/internal/priv"
)

// Client is one authorised caller. It is identified by the certificate's CN
// (= Name), or, if SPIFFEID is set, only by that SPIFFE ID (the
// certificate's single URI SAN). Either way the certificate must chain to
// the client's CA bundle, so a certificate from another CA that happens to
// carry the same name is not this client.
type Client struct {
	Name     string   `json:"name"`
	CA       string   `json:"ca,omitempty"`        // bundle name; may be omitted when there is one
	SPIFFEID string   `json:"spiffe_id,omitempty"` // spiffe://trust-domain/path
	Admin    bool     `json:"admin,omitempty"`
	ReadOnly bool     `json:"read_only,omitempty"`
	Anchors  []string `json:"anchors,omitempty"` // exact names, or "prefix*"
	Tables   []string `json:"tables,omitempty"`
	// QoS allows reading and replacing the firewall-wide QoS document
	// (queues and classification rules). It affects all traffic on the
	// queued interfaces, so it is a separate grant (admins have it).
	QoS bool `json:"qos,omitempty"`
}

func match(patterns []string, name string) bool {
	for _, p := range patterns {
		if p == "*" || p == name {
			return true
		}
		if pre, ok := strings.CutSuffix(p, "*"); ok && strings.HasPrefix(name, pre) {
			return true
		}
	}
	return false
}

func (c Client) canAnchor(name string) bool { return c.Admin || match(c.Anchors, name) }
func (c Client) canTable(name string) bool  { return c.Admin || match(c.Tables, name) }
func (c Client) canQoS() bool               { return c.Admin || c.QoS }

const maxBody = 1 << 20

type Server struct {
	backend priv.Backend
	clients map[string]Client // by identityKey
	log     *slog.Logger
	limit   *limiter
	trust   atomic.Pointer[Trust]
}

func identityKey(kind, bundle, id string) string { return kind + "\x00" + bundle + "\x00" + id }

// New checks the client list against the trust's CA bundles and indexes it.
func New(b priv.Backend, clients []Client, trust *Trust, rate float64, burst int, log *slog.Logger) (*Server, error) {
	m := make(map[string]Client, len(clients))
	names := map[string]bool{}
	bundles := trust.Bundles()
	for _, c := range clients {
		if !validCN(c.Name) {
			return nil, fmt.Errorf("api: client name %q", c.Name)
		}
		if names[c.Name] {
			return nil, fmt.Errorf("api: duplicate client %q", c.Name)
		}
		names[c.Name] = true
		key, err := clientIdentity(&c, bundles)
		if err != nil {
			return nil, err
		}
		if _, dup := m[key]; dup {
			return nil, fmt.Errorf("api: client %q: identity used twice", c.Name)
		}
		m[key] = c
	}
	if rate <= 0 {
		rate = 10
	}
	if burst <= 0 {
		burst = 40
	}
	s := &Server{backend: b, clients: m, log: log, limit: newLimiter(rate, burst)}
	s.trust.Store(trust)
	return s, nil
}

// clientIdentity resolves the client's CA bundle (defaulting it when there
// is only one) and returns the key it is identified by: its SPIFFE ID when
// set, otherwise its CN.
func clientIdentity(c *Client, bundles []string) (string, error) {
	switch {
	case c.CA == "" && len(bundles) == 1:
		c.CA = bundles[0]
	case c.CA == "":
		return "", fmt.Errorf("api: client %q: set ca (one of %s)", c.Name, strings.Join(bundles, ", "))
	case !slices.Contains(bundles, c.CA):
		return "", fmt.Errorf("api: client %q: unknown ca %q", c.Name, c.CA)
	}
	if c.SPIFFEID == "" {
		return identityKey("cn", c.CA, c.Name), nil
	}
	if !ValidSPIFFEID(c.SPIFFEID) {
		return "", fmt.Errorf("api: client %q: invalid spiffe_id %q", c.Name, c.SPIFFEID)
	}
	return identityKey("spiffe", c.CA, c.SPIFFEID), nil
}

// validCN: the client name is matched against the certificate CN, so allow
// any printable CN (e.g. "terraform.ci.example.com"), without spaces,
// quotes, backslashes or control characters.
func validCN(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, r := range s {
		if r <= ' ' || r == 0x7f || r == '"' || r == '\\' {
			return false
		}
	}
	return true
}

// SetTrust replaces the TLS material (certificate rotation). New handshakes
// use it at once. It refuses material that lacks a bundle a client needs.
func (s *Server) SetTrust(t *Trust) error {
	bundles := t.Bundles()
	for _, c := range s.clients {
		if !slices.Contains(bundles, c.CA) {
			return fmt.Errorf("client %q needs CA bundle %q, which the new material lacks", c.Name, c.CA)
		}
	}
	s.trust.Store(t)
	return nil
}

// TLSConfig is the listener configuration; every handshake uses the
// current Trust.
func (s *Server) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS13,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			return s.trust.Load().cfg, nil
		},
	}
}

// HTTPServer wraps the handler with conservative limits.
func (s *Server) HTTPServer(addr string, tc *tls.Config) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		TLSConfig:         tc,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    16 << 10,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelWarn),
	}
}

type handlerFunc func(w http.ResponseWriter, r *http.Request, c Client)

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	route := func(pattern string, h handlerFunc) { mux.Handle(pattern, s.wrap(h, false)) }
	// check is a POST that changes nothing: it renders and runs pfctl -n.
	// Read-only clients may call it, so a plan-only identity (e.g. merge
	// request pipelines) can run terraform plan, which validates new rules.
	check := func(pattern string, h handlerFunc) { mux.Handle(pattern, s.wrap(h, true)) }
	route("GET /v1/healthz", s.health)
	route("GET /v1/anchors", s.listAnchors)
	route("GET /v1/anchors/{name}", s.getAnchor)
	route("PUT /v1/anchors/{name}", s.putAnchor)
	route("DELETE /v1/anchors/{name}", s.deleteAnchor)
	check("POST /v1/anchors/{name}/validate", s.validateAnchor)
	route("GET /v1/anchors/{name}/drift", s.driftAnchor)
	route("GET /v1/tables", s.listTables)
	route("GET /v1/tables/{name}", s.getTable)
	route("PUT /v1/tables/{name}", s.putTable)
	route("GET /v1/tables/{name}/drift", s.driftTable)
	route("GET /v1/qos", s.getQoS)
	route("PUT /v1/qos", s.putQoS)
	check("POST /v1/qos/validate", s.validateQoS)
	route("GET /v1/qos/drift", s.driftQoS)
	route("GET /v1/changes/pending", s.pending)
	route("POST /v1/changes/{id}/confirm", s.confirm)
	route("POST /v1/changes/{id}/rollback", s.rollback)
	return mux
}

// identify maps the verified client certificate to a configured client. It
// also returns the certificate's own identity, for the audit log.
func (s *Server) identify(r *http.Request) (Client, string, bool) {
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 || len(r.TLS.VerifiedChains[0]) == 0 {
		return Client{}, "", false
	}
	leaf := r.TLS.VerifiedChains[0][0]
	sid := spiffeID(leaf)
	seen := leaf.Subject.CommonName
	if sid != "" {
		seen = sid
	}
	for _, bundle := range s.trust.Load().anchors(r.TLS.VerifiedChains) {
		if sid != "" {
			if c, ok := s.clients[identityKey("spiffe", bundle, sid)]; ok {
				return c, seen, true
			}
		}
		if c, ok := s.clients[identityKey("cn", bundle, leaf.Subject.CommonName)]; ok {
			return c, seen, true
		}
	}
	return Client{}, seen, false
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(c int) { w.status = c; w.ResponseWriter.WriteHeader(c) }

// wrap authenticates, rate-limits and logs every request. readSafe marks a
// route that changes no state although it is not a GET (the validate
// endpoints); read-only clients may call those.
func (s *Server) wrap(h handlerFunc, readSafe bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		c, seen, ok := s.identify(r)
		id := c.Name
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		defer func() {
			lvl := slog.LevelDebug
			if r.Method != http.MethodGet || sw.status >= 400 {
				lvl = slog.LevelInfo // audit every mutation and every failure
			}
			s.log.Log(r.Context(), lvl, "request", "client", id, "cert", seen, "method", r.Method, "path", r.URL.Path,
				"status", sw.status, "remote", r.RemoteAddr, "duration_ms", time.Since(start).Milliseconds())
		}()
		if !ok {
			writeErr(sw, http.StatusForbidden, priv.CodeForbidden, "client certificate not authorised")
			return
		}
		if !s.limit.allow(id) {
			sw.Header().Set("Retry-After", "1")
			writeErr(sw, http.StatusTooManyRequests, "rate_limited", "too many requests")
			return
		}
		if c.ReadOnly && r.Method != http.MethodGet && !readSafe {
			writeErr(sw, http.StatusForbidden, priv.CodeForbidden, "client is read-only")
			return
		}
		r.Body = http.MaxBytesReader(sw, r.Body, maxBody)
		h(sw, r, c)
	})
}

// --- helpers --------------------------------------------------------------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, map[string]any{"error": priv.Error{Code: code, Msg: msg}})
}

var statusOf = map[string]int{
	priv.CodeInvalid:      http.StatusBadRequest,
	priv.CodeNotFound:     http.StatusNotFound,
	priv.CodeConflict:     http.StatusConflict,
	priv.CodePrecondition: http.StatusPreconditionFailed,
	priv.CodePFRejected:   http.StatusUnprocessableEntity,
	priv.CodeForbidden:    http.StatusForbidden,
}

func (s *Server) fail(w http.ResponseWriter, err error) {
	e := priv.AsError(err)
	st, ok := statusOf[e.Code]
	if !ok {
		st = http.StatusInternalServerError
		s.log.Error("internal error", "err", e.Msg)
		e.Msg = "internal error" // details stay in the log
	}
	writeErr(w, st, e.Code, e.Msg)
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return &priv.Error{Code: priv.CodeInvalid, Msg: "request body: " + err.Error()}
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return &priv.Error{Code: priv.CodeInvalid, Msg: "request body: trailing data"}
	}
	return nil
}

func precondition(r *http.Request) priv.Precondition {
	p := priv.Precondition{IfNoneMatch: strings.TrimSpace(r.Header.Get("If-None-Match")) == "*"}
	p.IfMatch = strings.Trim(strings.TrimSpace(r.Header.Get("If-Match")), `"`)
	return p
}

func setETag(w http.ResponseWriter, etag string) {
	if etag != "" {
		w.Header().Set("ETag", `"`+etag+`"`)
	}
}

func (s *Server) anchorName(w http.ResponseWriter, r *http.Request, c Client) (string, bool) {
	name := r.PathValue("name")
	if !model.ValidName(name) {
		writeErr(w, http.StatusBadRequest, priv.CodeInvalid, "invalid anchor name")
		return "", false
	}
	if !c.canAnchor(name) {
		writeErr(w, http.StatusForbidden, priv.CodeForbidden, "anchor not in client scope")
		return "", false
	}
	return name, true
}

func (s *Server) tableName(w http.ResponseWriter, r *http.Request, c Client) (string, bool) {
	name := r.PathValue("name")
	if !model.ValidName(name) {
		writeErr(w, http.StatusBadRequest, priv.CodeInvalid, "invalid table name")
		return "", false
	}
	if !c.canTable(name) {
		writeErr(w, http.StatusForbidden, priv.CodeForbidden, "table not in client scope")
		return "", false
	}
	return name, true
}

// body of PUT /v1/anchors/{name}: the name comes from the path.
type anchorBody struct {
	Rules []model.Rule `json:"rules"`
}

type tableBody struct {
	Entries []string `json:"entries"`
}

// --- handlers -------------------------------------------------------------

func (s *Server) health(w http.ResponseWriter, _ *http.Request, c Client) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "client": c.Name})
}

func (s *Server) listAnchors(w http.ResponseWriter, r *http.Request, c Client) {
	names, err := s.backend.ListAnchors(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	out := []string{}
	for _, n := range names {
		if c.canAnchor(n) {
			out = append(out, n)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"anchors": out})
}

func (s *Server) getAnchor(w http.ResponseWriter, r *http.Request, c Client) {
	name, ok := s.anchorName(w, r, c)
	if !ok {
		return
	}
	st, err := s.backend.GetAnchor(r.Context(), name)
	if err != nil {
		s.fail(w, err)
		return
	}
	setETag(w, st.ETag)
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) putAnchor(w http.ResponseWriter, r *http.Request, c Client) {
	name, ok := s.anchorName(w, r, c)
	if !ok {
		return
	}
	var b anchorBody
	if err := decode(r, &b); err != nil {
		s.fail(w, err)
		return
	}
	ci, err := s.backend.PutAnchor(r.Context(), c.Name, model.Anchor{Name: name, Rules: b.Rules}, precondition(r))
	if err != nil {
		s.fail(w, err)
		return
	}
	s.accepted(w, ci)
}

func (s *Server) deleteAnchor(w http.ResponseWriter, r *http.Request, c Client) {
	name, ok := s.anchorName(w, r, c)
	if !ok {
		return
	}
	ci, err := s.backend.DeleteAnchor(r.Context(), c.Name, name, precondition(r))
	if err != nil {
		s.fail(w, err)
		return
	}
	s.accepted(w, ci)
}

func (s *Server) accepted(w http.ResponseWriter, ci priv.ChangeInfo) {
	w.Header().Set("Location", "/v1/changes/"+ci.ID)
	s.log.Info("change pending", "change", ci.ID, "client", ci.Actor, "kind", ci.Kind, "name", ci.Name, "op", ci.Op)
	writeJSON(w, http.StatusAccepted, ci)
}

func (s *Server) validateAnchor(w http.ResponseWriter, r *http.Request, c Client) {
	name, ok := s.anchorName(w, r, c)
	if !ok {
		return
	}
	var b anchorBody
	if err := decode(r, &b); err != nil {
		s.fail(w, err)
		return
	}
	res, err := s.backend.ValidateAnchor(r.Context(), model.Anchor{Name: name, Rules: b.Rules})
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) driftAnchor(w http.ResponseWriter, r *http.Request, c Client) {
	name, ok := s.anchorName(w, r, c)
	if !ok {
		return
	}
	res, err := s.backend.DriftAnchor(r.Context(), name)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) listTables(w http.ResponseWriter, r *http.Request, c Client) {
	names, err := s.backend.ListTables(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	out := []string{}
	for _, n := range names {
		if c.canTable(n) {
			out = append(out, n)
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"tables": out})
}

func (s *Server) getTable(w http.ResponseWriter, r *http.Request, c Client) {
	name, ok := s.tableName(w, r, c)
	if !ok {
		return
	}
	st, err := s.backend.GetTable(r.Context(), name)
	if err != nil {
		s.fail(w, err)
		return
	}
	setETag(w, st.ETag)
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) putTable(w http.ResponseWriter, r *http.Request, c Client) {
	name, ok := s.tableName(w, r, c)
	if !ok {
		return
	}
	var b tableBody
	if err := decode(r, &b); err != nil {
		s.fail(w, err)
		return
	}
	t := model.Table{Name: name}
	for _, e := range b.Entries {
		p, err := parseEntry(e)
		if err != nil {
			writeErr(w, http.StatusBadRequest, priv.CodeInvalid, err.Error())
			return
		}
		t.Entries = append(t.Entries, p)
	}
	ci, err := s.backend.PutTable(r.Context(), c.Name, t, precondition(r))
	if err != nil {
		s.fail(w, err)
		return
	}
	s.accepted(w, ci)
}

func (s *Server) driftTable(w http.ResponseWriter, r *http.Request, c Client) {
	name, ok := s.tableName(w, r, c)
	if !ok {
		return
	}
	res, err := s.backend.DriftTable(r.Context(), name)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) qosAllowed(w http.ResponseWriter, c Client) bool {
	if !c.canQoS() {
		writeErr(w, http.StatusForbidden, priv.CodeForbidden, "client has no QoS grant")
		return false
	}
	return true
}

func (s *Server) getQoS(w http.ResponseWriter, r *http.Request, c Client) {
	if !s.qosAllowed(w, c) {
		return
	}
	st, err := s.backend.GetQoS(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	setETag(w, st.ETag)
	writeJSON(w, http.StatusOK, st)
}

func (s *Server) putQoS(w http.ResponseWriter, r *http.Request, c Client) {
	if !s.qosAllowed(w, c) {
		return
	}
	var q model.QoS
	if err := decode(r, &q); err != nil {
		s.fail(w, err)
		return
	}
	ci, err := s.backend.PutQoS(r.Context(), c.Name, q, precondition(r))
	if err != nil {
		s.fail(w, err)
		return
	}
	s.accepted(w, ci)
}

func (s *Server) validateQoS(w http.ResponseWriter, r *http.Request, c Client) {
	if !s.qosAllowed(w, c) {
		return
	}
	var q model.QoS
	if err := decode(r, &q); err != nil {
		s.fail(w, err)
		return
	}
	res, err := s.backend.ValidateQoS(r.Context(), q)
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) driftQoS(w http.ResponseWriter, r *http.Request, c Client) {
	if !s.qosAllowed(w, c) {
		return
	}
	res, err := s.backend.DriftQoS(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (s *Server) pending(w http.ResponseWriter, r *http.Request, _ Client) {
	ci, err := s.backend.Pending(r.Context())
	if err != nil {
		s.fail(w, err)
		return
	}
	if ci == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	writeJSON(w, http.StatusOK, ci)
}

func (s *Server) changeID(w http.ResponseWriter, r *http.Request) (string, bool) {
	id := r.PathValue("id")
	if len(id) != 16 || strings.Trim(id, "0123456789abcdef") != "" {
		writeErr(w, http.StatusBadRequest, priv.CodeInvalid, "invalid change id")
		return "", false
	}
	return id, true
}

func (s *Server) confirm(w http.ResponseWriter, r *http.Request, c Client) {
	id, ok := s.changeID(w, r)
	if !ok {
		return
	}
	if err := s.backend.Confirm(r.Context(), c.Name, id, c.Admin); err != nil {
		s.fail(w, err)
		return
	}
	s.log.Info("change confirmed", "change", id, "client", c.Name)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) rollback(w http.ResponseWriter, r *http.Request, c Client) {
	id, ok := s.changeID(w, r)
	if !ok {
		return
	}
	if err := s.backend.Rollback(r.Context(), c.Name, id, c.Admin); err != nil {
		s.fail(w, err)
		return
	}
	s.log.Info("change rolled back", "change", id, "client", c.Name)
	w.WriteHeader(http.StatusNoContent)
}

// --- rate limiting -------------------------------------------------------

type bucket struct {
	tokens float64
	last   time.Time
}

type limiter struct {
	mu      sync.Mutex
	rate    float64
	burst   float64
	buckets map[string]*bucket
	now     func() time.Time
}

func newLimiter(rate float64, burst int) *limiter {
	return &limiter{rate: rate, burst: float64(burst), buckets: map[string]*bucket{}, now: time.Now}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

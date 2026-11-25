package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/pderuiter/pfapid/internal/model"
	"github.com/pderuiter/pfapid/internal/priv"
)

// fake is a complete Backend. err, when set, is returned by every call;
// calls records "method:arg" for every call that reached it.
type fake struct {
	err     error
	pending *priv.ChangeInfo
	calls   []string
	table   model.Table
	pre     priv.Precondition
}

func (f *fake) rec(s string) error { f.calls = append(f.calls, s); return f.err }

func (f *fake) ListAnchors(context.Context) ([]string, error) {
	return []string{"k8s-prod", "other"}, f.rec("ListAnchors")
}
func (f *fake) GetAnchor(_ context.Context, n string) (priv.AnchorState, error) {
	return priv.AnchorState{Anchor: model.Anchor{Name: n}, ETag: "e1"}, f.rec("GetAnchor:" + n)
}
func (f *fake) PutAnchor(_ context.Context, actor string, a model.Anchor, pre priv.Precondition) (priv.ChangeInfo, error) {
	f.pre = pre
	return priv.ChangeInfo{ID: "00000000000000aa", Actor: actor, Kind: "anchor", Name: a.Name, Op: "put"}, f.rec("PutAnchor:" + a.Name)
}
func (f *fake) DeleteAnchor(_ context.Context, actor, n string, pre priv.Precondition) (priv.ChangeInfo, error) {
	f.pre = pre
	return priv.ChangeInfo{ID: "00000000000000bb", Actor: actor, Kind: "anchor", Name: n, Op: "delete"}, f.rec("DeleteAnchor:" + n)
}
func (f *fake) ValidateAnchor(_ context.Context, a model.Anchor) (priv.ValidateResult, error) {
	return priv.ValidateResult{Rendered: []string{"pass in"}, Normalised: []string{"pass in all"}}, f.rec("ValidateAnchor:" + a.Name)
}
func (f *fake) DriftAnchor(_ context.Context, n string) (priv.DriftResult, error) {
	return priv.DriftResult{InSync: true}, f.rec("DriftAnchor:" + n)
}
func (f *fake) ListTables(context.Context) ([]string, error) {
	return []string{"k8s_nodes", "secret"}, f.rec("ListTables")
}
func (f *fake) GetTable(_ context.Context, n string) (priv.TableState, error) {
	return priv.TableState{Table: model.Table{Name: n}, ETag: "t1"}, f.rec("GetTable:" + n)
}
func (f *fake) PutTable(_ context.Context, actor string, t model.Table, pre priv.Precondition) (priv.ChangeInfo, error) {
	f.table, f.pre = t, pre
	return priv.ChangeInfo{ID: "00000000000000cc", Actor: actor, Kind: "table", Name: t.Name, Op: "put"}, f.rec("PutTable:" + t.Name)
}
func (f *fake) DriftTable(_ context.Context, n string) (priv.DriftResult, error) {
	return priv.DriftResult{InSync: false, Live: []string{"10.0.0.1/32"}}, f.rec("DriftTable:" + n)
}
func (f *fake) GetQoS(context.Context) (priv.QoSState, error) {
	return priv.QoSState{ETag: "q1"}, f.rec("GetQoS")
}
func (f *fake) PutQoS(_ context.Context, actor string, _ model.QoS, pre priv.Precondition) (priv.ChangeInfo, error) {
	f.pre = pre
	return priv.ChangeInfo{ID: "00000000000000dd", Actor: actor, Kind: "qos", Name: "qos"}, f.rec("PutQoS")
}
func (f *fake) ValidateQoS(context.Context, model.QoS) (priv.ValidateResult, error) {
	return priv.ValidateResult{Rendered: []string{"queue q"}}, f.rec("ValidateQoS")
}
func (f *fake) DriftQoS(context.Context) (priv.DriftResult, error) {
	return priv.DriftResult{InSync: true}, f.rec("DriftQoS")
}
func (f *fake) Pending(context.Context) (*priv.ChangeInfo, error) {
	return f.pending, f.rec("Pending")
}
func (f *fake) Confirm(_ context.Context, actor, id string, admin bool) error {
	return f.rec("Confirm:" + id + ":" + actor + ":" + map[bool]string{true: "admin", false: "user"}[admin])
}
func (f *fake) Rollback(_ context.Context, actor, id string, admin bool) error {
	return f.rec("Rollback:" + id + ":" + actor + ":" + map[bool]string{true: "admin", false: "user"}[admin])
}

var handlerClients = []Client{
	{Name: "tf-prod", Anchors: []string{"k8s-*"}, Tables: []string{"k8s_nodes"}},
	{Name: "reader", ReadOnly: true, Anchors: []string{"*"}, Tables: []string{"*"}},
	{Name: "admin", Admin: true},
	{Name: "netops", QoS: true},
	{Name: "planner", ReadOnly: true, Anchors: []string{"k8s-*"}},
}

func decodeJSON(t *testing.T, body string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(body), v); err != nil {
		t.Fatalf("response %q: %v", body, err)
	}
}

// wantStatus fails the test when resp does not carry the expected status.
func wantStatus(t *testing.T, resp *http.Response, code int, what string) {
	t.Helper()
	if resp.StatusCode != code {
		t.Fatalf("%s: status %d, want %d", what, resp.StatusCode, code)
	}
}

func TestAnchorHandlers(t *testing.T) {
	f := &fake{}
	p, url := start(t, f, handlerClients)
	c := client(p, "tf-prod")

	anchorDelete(t, c, url, f)
	anchorValidate(t, c, url)
	resp := anchorDrift(t, c, url)

	// Security headers on every response.
	if resp.Header.Get("Cache-Control") != "no-store" || resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("headers: %v", resp.Header)
	}
	want := []string{"DeleteAnchor:k8s-prod", "ValidateAnchor:k8s-prod", "DriftAnchor:k8s-prod"}
	if strings.Join(f.calls, ",") != strings.Join(want, ",") {
		t.Fatalf("backend calls: %v", f.calls)
	}
}

// anchorDelete: 202, Location, precondition forwarded; out of scope never
// reaches the backend.
func anchorDelete(t *testing.T, c *http.Client, url string, f *fake) {
	t.Helper()
	resp, body := do(t, c, "DELETE", url+"/v1/anchors/k8s-prod", "", map[string]string{"If-Match": ` "e1" `})
	if resp.StatusCode != http.StatusAccepted || resp.Header.Get("Location") != "/v1/changes/00000000000000bb" {
		t.Fatalf("delete: %d %v %s", resp.StatusCode, resp.Header, body)
	}
	if f.pre.IfMatch != "e1" || f.pre.IfNoneMatch {
		t.Fatalf("precondition: %+v", f.pre)
	}
	var ci priv.ChangeInfo
	decodeJSON(t, body, &ci)
	if ci.Op != "delete" || ci.Actor != "tf-prod" {
		t.Fatalf("change info: %+v", ci)
	}
	resp, _ = do(t, c, "DELETE", url+"/v1/anchors/other", "", nil)
	wantStatus(t, resp, http.StatusForbidden, "delete out of scope")
}

// anchorValidate returns the rendered and normalised rules.
func anchorValidate(t *testing.T, c *http.Client, url string) {
	t.Helper()
	resp, body := do(t, c, "POST", url+"/v1/anchors/k8s-prod/validate", ruleBody, nil)
	var vr priv.ValidateResult
	decodeJSON(t, body, &vr)
	if resp.StatusCode != http.StatusOK || len(vr.Rendered) != 1 || vr.Normalised[0] != "pass in all" {
		t.Fatalf("validate: %d %s", resp.StatusCode, body)
	}
	resp, _ = do(t, c, "POST", url+"/v1/anchors/k8s-prod/validate", `{"bogus":1}`, nil)
	wantStatus(t, resp, http.StatusBadRequest, "validate bad body")
	resp, _ = do(t, c, "POST", url+"/v1/anchors/BAD/validate", ruleBody, nil)
	wantStatus(t, resp, http.StatusBadRequest, "validate bad name")
}

func anchorDrift(t *testing.T, c *http.Client, url string) *http.Response {
	t.Helper()
	resp, body := do(t, c, "GET", url+"/v1/anchors/k8s-prod/drift", "", nil)
	var dr priv.DriftResult
	decodeJSON(t, body, &dr)
	if resp.StatusCode != http.StatusOK || !dr.InSync {
		t.Fatalf("drift: %d %s", resp.StatusCode, body)
	}
	out, _ := do(t, c, "GET", url+"/v1/anchors/other/drift", "", nil)
	wantStatus(t, out, http.StatusForbidden, "drift out of scope")
	return resp
}

func TestTableHandlers(t *testing.T) {
	f := &fake{}
	p, url := start(t, f, handlerClients)
	c := client(p, "tf-prod")

	tableRead(t, p, c, url)
	tablePut(t, c, url, f)
	tableDrift(t, c, url)
}

// tableRead: lists are filtered by scope (admin sees all), GET carries the ETag.
func tableRead(t *testing.T, p *pki, c *http.Client, url string) {
	t.Helper()
	_, body := do(t, c, "GET", url+"/v1/tables", "", nil)
	if !strings.Contains(body, "k8s_nodes") || strings.Contains(body, "secret") {
		t.Fatalf("table list not filtered: %s", body)
	}
	_, body = do(t, client(p, "admin"), "GET", url+"/v1/tables", "", nil)
	if !strings.Contains(body, "secret") {
		t.Fatalf("admin sees every table: %s", body)
	}
	resp, body := do(t, c, "GET", url+"/v1/tables/k8s_nodes", "", nil)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("ETag") != `"t1"` {
		t.Fatalf("get table: %d %v %s", resp.StatusCode, resp.Header, body)
	}
	resp, _ = do(t, c, "GET", url+"/v1/tables/secret", "", nil)
	wantStatus(t, resp, http.StatusForbidden, "table out of scope")
	resp, _ = do(t, c, "GET", url+"/v1/tables/Bad.Name", "", nil)
	wantStatus(t, resp, http.StatusBadRequest, "bad table name")
}

// tablePut: bare addresses become host prefixes, prefixes are kept; bad
// entries never reach the backend.
func tablePut(t *testing.T, c *http.Client, url string, f *fake) {
	t.Helper()
	resp, body := do(t, c, "PUT", url+"/v1/tables/k8s_nodes",
		`{"entries":["10.0.0.1","2001:db8::1","192.0.2.0/24"]}`, map[string]string{"If-None-Match": "*"})
	if resp.StatusCode != http.StatusAccepted || resp.Header.Get("Location") != "/v1/changes/00000000000000cc" {
		t.Fatalf("put table: %d %s", resp.StatusCode, body)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.1/32"), netip.MustParsePrefix("2001:db8::1/128"), netip.MustParsePrefix("192.0.2.0/24"),
	}
	if len(f.table.Entries) != len(want) || !f.pre.IfNoneMatch {
		t.Fatalf("table sent: %+v pre %+v", f.table, f.pre)
	}
	for i := range want {
		if f.table.Entries[i] != want[i] {
			t.Fatalf("entry %d: %s, want %s", i, f.table.Entries[i], want[i])
		}
	}
	n := len(f.calls)
	resp, body = do(t, c, "PUT", url+"/v1/tables/k8s_nodes", `{"entries":["not-an-ip"]}`, nil)
	if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "not-an-ip") || len(f.calls) != n {
		t.Fatalf("bad entry: %d %s (calls %v)", resp.StatusCode, body, f.calls)
	}
	resp, _ = do(t, c, "PUT", url+"/v1/tables/k8s_nodes", `{"entries":"x"}`, nil)
	wantStatus(t, resp, http.StatusBadRequest, "bad body")
}

func tableDrift(t *testing.T, c *http.Client, url string) {
	t.Helper()
	resp, body := do(t, c, "GET", url+"/v1/tables/k8s_nodes/drift", "", nil)
	var dr priv.DriftResult
	decodeJSON(t, body, &dr)
	if resp.StatusCode != http.StatusOK || dr.InSync || dr.Live[0] != "10.0.0.1/32" {
		t.Fatalf("table drift: %d %s", resp.StatusCode, body)
	}
	resp, _ = do(t, c, "GET", url+"/v1/tables/secret/drift", "", nil)
	wantStatus(t, resp, http.StatusForbidden, "drift out of scope")
}

func TestQoSHandlers(t *testing.T) {
	f := &fake{}
	p, url := start(t, f, handlerClients)
	c := client(p, "netops")

	resp, body := do(t, c, "GET", url+"/v1/qos", "", nil)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("ETag") != `"q1"` {
		t.Fatalf("get qos: %d %s", resp.StatusCode, body)
	}
	resp, body = do(t, c, "POST", url+"/v1/qos/validate", `{"queues":[],"rules":[]}`, nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "queue q") {
		t.Fatalf("validate qos: %d %s", resp.StatusCode, body)
	}
	if resp, _ := do(t, c, "POST", url+"/v1/qos/validate", `{"x":1}`, nil); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("validate qos bad body: %d", resp.StatusCode)
	}
	if resp, body := do(t, c, "GET", url+"/v1/qos/drift", "", nil); resp.StatusCode != http.StatusOK || !strings.Contains(body, `"in_sync":true`) {
		t.Fatalf("qos drift: %d %s", resp.StatusCode, body)
	}
	// Without the grant every QoS route is forbidden and never reaches the backend.
	n := len(f.calls)
	for _, r := range []struct{ method, path, body string }{
		{"GET", "/v1/qos", ""}, {"POST", "/v1/qos/validate", `{}`}, {"GET", "/v1/qos/drift", ""},
	} {
		if resp, _ := do(t, client(p, "tf-prod"), r.method, url+r.path, r.body, nil); resp.StatusCode != http.StatusForbidden {
			t.Fatalf("%s %s without grant: %d", r.method, r.path, resp.StatusCode)
		}
	}
	if len(f.calls) != n {
		t.Fatalf("forbidden requests reached the backend: %v", f.calls[n:])
	}
}

func TestChangeHandlers(t *testing.T) {
	f := &fake{}
	p, url := start(t, f, handlerClients)
	c := client(p, "tf-prod")

	if resp, _ := do(t, c, "GET", url+"/v1/changes/pending", "", nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("no pending change: %d", resp.StatusCode)
	}
	f.pending = &priv.ChangeInfo{ID: "00000000000000aa", Actor: "tf-prod", Deadline: time.Unix(100, 0).UTC()}
	resp, body := do(t, c, "GET", url+"/v1/changes/pending", "", nil)
	var ci priv.ChangeInfo
	decodeJSON(t, body, &ci)
	if resp.StatusCode != http.StatusOK || ci.ID != "00000000000000aa" {
		t.Fatalf("pending: %d %s", resp.StatusCode, body)
	}

	if resp, _ := do(t, c, "POST", url+"/v1/changes/00000000000000aa/rollback", "", nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("rollback: %d", resp.StatusCode)
	}
	if resp, _ := do(t, client(p, "admin"), "POST", url+"/v1/changes/00000000000000aa/rollback", "", nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("admin rollback: %d", resp.StatusCode)
	}
	if resp, _ := do(t, c, "POST", url+"/v1/changes/ABCDEF0123456789/rollback", "", nil); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("upper-case id: %d", resp.StatusCode)
	}
	got := strings.Join(f.calls, ",")
	if !strings.Contains(got, "Rollback:00000000000000aa:tf-prod:user") || !strings.Contains(got, "Rollback:00000000000000aa:admin:admin") {
		t.Fatalf("calls: %v", f.calls)
	}
	// Read-only clients cannot confirm or roll back.
	if resp, _ := do(t, client(p, "reader"), "POST", url+"/v1/changes/00000000000000aa/confirm", "", nil); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("read-only confirm: %d", resp.StatusCode)
	}
}

// Backend errors map to HTTP status codes; internal errors never leak details.
func TestBackendErrors(t *testing.T) {
	f := &fake{}
	p, url := start(t, f, handlerClients)
	c := client(p, "admin")
	cases := []struct {
		err  error
		want int
	}{
		{&priv.Error{Code: priv.CodeInvalid, Msg: "bad"}, http.StatusBadRequest},
		{&priv.Error{Code: priv.CodeNotFound, Msg: "gone"}, http.StatusNotFound},
		{&priv.Error{Code: priv.CodeConflict, Msg: "busy"}, http.StatusConflict},
		{&priv.Error{Code: priv.CodePrecondition, Msg: "etag"}, http.StatusPreconditionFailed},
		{&priv.Error{Code: priv.CodePFRejected, Msg: "pfctl"}, http.StatusUnprocessableEntity},
		{&priv.Error{Code: priv.CodeForbidden, Msg: "no"}, http.StatusForbidden},
		{errors.New("disk on fire at /var/db/pfapid"), http.StatusInternalServerError},
	}
	routes := []struct{ method, path, body string }{
		{"GET", "/v1/anchors", ""},
		{"GET", "/v1/anchors/k8s-prod", ""},
		{"PUT", "/v1/anchors/k8s-prod", ruleBody},
		{"DELETE", "/v1/anchors/k8s-prod", ""},
		{"POST", "/v1/anchors/k8s-prod/validate", ruleBody},
		{"GET", "/v1/anchors/k8s-prod/drift", ""},
		{"GET", "/v1/tables", ""},
		{"GET", "/v1/tables/k8s_nodes", ""},
		{"PUT", "/v1/tables/k8s_nodes", `{"entries":[]}`},
		{"GET", "/v1/tables/k8s_nodes/drift", ""},
		{"GET", "/v1/qos", ""},
		{"PUT", "/v1/qos", `{"queues":[],"rules":[]}`},
		{"POST", "/v1/qos/validate", `{"queues":[],"rules":[]}`},
		{"GET", "/v1/qos/drift", ""},
		{"GET", "/v1/changes/pending", ""},
		{"POST", "/v1/changes/00000000000000aa/confirm", ""},
		{"POST", "/v1/changes/00000000000000aa/rollback", ""},
	}
	for _, tc := range cases {
		f.err = tc.err
		for _, r := range routes {
			resp, body := do(t, c, r.method, url+r.path, r.body, nil)
			if resp == nil || resp.StatusCode != tc.want {
				t.Fatalf("%s %s with %v: got %v %s", r.method, r.path, tc.err, resp, body)
			}
			if tc.want == http.StatusInternalServerError && strings.Contains(body, "disk on fire") {
				t.Fatalf("internal error details leaked: %s", body)
			}
		}
	}
}

func TestParseEntry(t *testing.T) {
	for in, want := range map[string]string{
		"10.0.0.1": "10.0.0.1/32", "10.0.0.0/8": "10.0.0.0/8", "2001:db8::1": "2001:db8::1/128", "2001:db8::/32": "2001:db8::/32",
	} {
		p, err := parseEntry(in)
		if err != nil || p.String() != want {
			t.Errorf("parseEntry(%q) = %v, %v; want %s", in, p, err, want)
		}
	}
	for _, in := range []string{"", "host.example", "10.0.0.256", "10.0.0.0/33"} {
		if _, err := parseEntry(in); err == nil {
			t.Errorf("parseEntry(%q) accepted", in)
		}
	}
}

func TestHTTPServerLimits(t *testing.T) {
	p := newPKI(t)
	tr, err := NewTrust(p.material(nil))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(&fake{}, nil, tr, 0, 0, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	if s.limit.rate != 10 || s.limit.burst != 40 {
		t.Fatalf("default rate limits: %v/%v", s.limit.rate, s.limit.burst)
	}
	hs := s.HTTPServer("127.0.0.1:0", s.TLSConfig())
	if hs.Addr != "127.0.0.1:0" || hs.Handler == nil || hs.TLSConfig == nil || hs.ErrorLog == nil {
		t.Fatalf("server: %+v", hs)
	}
	if hs.ReadHeaderTimeout == 0 || hs.ReadTimeout == 0 || hs.WriteTimeout == 0 || hs.IdleTimeout == 0 || hs.MaxHeaderBytes == 0 {
		t.Fatalf("missing limits: %+v", hs)
	}
}

func TestRateLimitedRequest(t *testing.T) {
	p := newPKI(t, "tf-prod")
	tr, err := NewTrust(p.material(nil))
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(&fake{}, handlerClients[:1], tr, 0.001, 1, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(s.Handler())
	ts.TLS = s.TLSConfig()
	ts.StartTLS()
	t.Cleanup(ts.Close)
	c := client(p, "tf-prod")
	if resp, _ := do(t, c, "GET", ts.URL+"/v1/healthz", "", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("first request: %d", resp.StatusCode)
	}
	resp, _ := do(t, c, "GET", ts.URL+"/v1/healthz", "", nil)
	if resp.StatusCode != http.StatusTooManyRequests || resp.Header.Get("Retry-After") != "1" {
		t.Fatalf("second request: %d %v", resp.StatusCode, resp.Header)
	}
}

// A read-only client may validate (a POST that changes nothing), so a
// plan-only identity can run terraform plan; it still cannot write, and its
// anchor scope still applies.
func TestReadOnlyMayValidate(t *testing.T) {
	f := &fake{}
	p, url := start(t, f, handlerClients)
	c := client(p, "planner")

	anchorValidate(t, c, url)
	resp, _ := do(t, c, "POST", url+"/v1/anchors/other/validate", ruleBody, nil)
	wantStatus(t, resp, http.StatusForbidden, "read-only validate out of scope")
	resp, _ = do(t, c, "PUT", url+"/v1/anchors/k8s-prod", ruleBody, map[string]string{"If-None-Match": "*"})
	wantStatus(t, resp, http.StatusForbidden, "read-only put")
	resp, _ = do(t, c, "DELETE", url+"/v1/anchors/k8s-prod", "", map[string]string{"If-Match": `"x"`})
	wantStatus(t, resp, http.StatusForbidden, "read-only delete")
	resp, _ = do(t, c, "POST", url+"/v1/changes/00000000000000aa/confirm", "", nil)
	wantStatus(t, resp, http.StatusForbidden, "read-only confirm")
	// QoS validation is read-safe too, but still needs the qos grant.
	resp, _ = do(t, c, "POST", url+"/v1/qos/validate", `{}`, nil)
	wantStatus(t, resp, http.StatusForbidden, "read-only qos validate without grant")

	for _, call := range f.calls {
		if !strings.HasPrefix(call, "ValidateAnchor:") {
			t.Fatalf("read-only client reached the backend with %q", call)
		}
	}
}

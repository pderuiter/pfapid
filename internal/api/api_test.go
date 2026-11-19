package api

import (
	"context"
	"crypto/tls"
	"encoding/pem"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pderuiter/pfapid/internal/model"
	"github.com/pderuiter/pfapid/internal/priv"
)

// stub records what reached the backend.
type stub struct {
	priv.Backend
	puts []string
	pre  priv.Precondition
}

func (s *stub) ListAnchors(context.Context) ([]string, error) {
	return []string{"k8s-prod", "k8s-dev", "other"}, nil
}
func (s *stub) GetAnchor(_ context.Context, name string) (priv.AnchorState, error) {
	return priv.AnchorState{Anchor: model.Anchor{Name: name}, ETag: "abc"}, nil
}
func (s *stub) PutAnchor(_ context.Context, actor string, a model.Anchor, pre priv.Precondition) (priv.ChangeInfo, error) {
	s.puts = append(s.puts, actor+":"+a.Name)
	s.pre = pre
	return priv.ChangeInfo{ID: "0123456789abcdef", Actor: actor, Kind: "anchor", Name: a.Name}, nil
}
func (s *stub) Confirm(context.Context, string, string, bool) error { return nil }
func (s *stub) PutQoS(_ context.Context, actor string, q model.QoS, pre priv.Precondition) (priv.ChangeInfo, error) {
	s.puts = append(s.puts, actor+":qos")
	s.pre = pre
	return priv.ChangeInfo{ID: "0123456789abcdef", Actor: actor, Kind: "qos", Name: "qos"}, nil
}

var testClients = []Client{
	{Name: "tf-prod", Anchors: []string{"k8s-prod"}, Tables: []string{"k8s_nodes"}},
	{Name: "reader", ReadOnly: true, Anchors: []string{"k8s-*"}},
	{Name: "admin", Admin: true},
	{Name: "netops", QoS: true},
}

func do(t *testing.T, c *http.Client, method, url, body string, hdr map[string]string) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest(method, url, strings.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, err.Error()
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

const ruleBody = `{"rules":[{"action":"pass","direction":"in","interface":"frontend","family":"inet","protocol":"tcp","from":{},"to":{"ports":[{"from":443}]}}]}`

func TestAuthz(t *testing.T) {
	b := &stub{}
	p, url := start(t, b, testClients)

	// No client certificate: the TLS handshake fails.
	if resp, _ := do(t, client(p, "none"), "GET", url+"/v1/healthz", "", nil); resp != nil {
		t.Fatalf("request without client cert got %d", resp.StatusCode)
	}
	// Valid certificate, but not a configured client.
	if resp, _ := do(t, client(p, "stranger"), "GET", url+"/v1/healthz", "", nil); resp.StatusCode != 403 {
		t.Fatalf("stranger: %d", resp.StatusCode)
	}
	// Scope: tf-prod sees only its anchor.
	_, body := do(t, client(p, "tf-prod"), "GET", url+"/v1/anchors", "", nil)
	if !strings.Contains(body, "k8s-prod") || strings.Contains(body, "k8s-dev") {
		t.Fatalf("list not filtered: %s", body)
	}
	if resp, _ := do(t, client(p, "tf-prod"), "PUT", url+"/v1/anchors/k8s-dev", ruleBody, map[string]string{"If-None-Match": "*"}); resp.StatusCode != 403 {
		t.Fatalf("out of scope put: %d", resp.StatusCode)
	}
	resp, _ := do(t, client(p, "tf-prod"), "PUT", url+"/v1/anchors/k8s-prod", ruleBody, map[string]string{"If-Match": `"abc"`})
	if resp.StatusCode != 202 || resp.Header.Get("Location") != "/v1/changes/0123456789abcdef" {
		t.Fatalf("put: %d %v", resp.StatusCode, resp.Header)
	}
	if b.pre.IfMatch != "abc" || len(b.puts) != 1 || b.puts[0] != "tf-prod:k8s-prod" {
		t.Fatalf("backend got %+v %v", b.pre, b.puts)
	}
	// Read-only client.
	if resp, _ := do(t, client(p, "reader"), "PUT", url+"/v1/anchors/k8s-dev", ruleBody, nil); resp.StatusCode != 403 {
		t.Fatalf("read-only put: %d", resp.StatusCode)
	}
	if resp, _ := do(t, client(p, "reader"), "GET", url+"/v1/anchors/k8s-dev", "", nil); resp.StatusCode != 200 || resp.Header.Get("ETag") != `"abc"` {
		t.Fatalf("read-only get: %d %v", resp.StatusCode, resp.Header)
	}
	// Admin can confirm.
	if resp, _ := do(t, client(p, "admin"), "POST", url+"/v1/changes/0123456789abcdef/confirm", "", nil); resp.StatusCode != 204 {
		t.Fatalf("confirm: %d", resp.StatusCode)
	}
}

func TestInputHandling(t *testing.T) {
	p, url := start(t, &stub{}, testClients)
	c := client(p, "tf-prod")
	cases := []struct {
		name, method, path, body string
		want                     int
	}{
		{"unknown field", "PUT", "/v1/anchors/k8s-prod", `{"rules":[],"extra":1}`, 400},
		{"trailing data", "PUT", "/v1/anchors/k8s-prod", `{"rules":[]} {}`, 400},
		{"bad name", "GET", "/v1/anchors/Bad_Name", "", 400},
		{"bad change id", "POST", "/v1/changes/xyz/confirm", "", 400},
		{"oversized body", "PUT", "/v1/anchors/k8s-prod", `{"rules":[` + strings.Repeat(" ", maxBody) + `]}`, 400},
		{"unknown route", "GET", "/v2/anchors", "", 404},
	}
	for _, tc := range cases {
		resp, body := do(t, c, tc.method, url+tc.path, tc.body, nil)
		if resp == nil || resp.StatusCode != tc.want {
			t.Errorf("%s: want %d, got %v %s", tc.name, tc.want, resp, body)
		}
	}
}

func TestRateLimit(t *testing.T) {
	l := newLimiter(1, 2)
	now := time.Unix(0, 0)
	l.now = func() time.Time { return now }
	got := []bool{l.allow("a"), l.allow("a"), l.allow("a")}
	if !got[0] || !got[1] || got[2] {
		t.Fatalf("burst of 2 not enforced: %v", got)
	}
	if !l.allow("b") {
		t.Fatal("limits must be per client")
	}
	now = now.Add(time.Second)
	if !l.allow("a") {
		t.Fatal("tokens not refilled")
	}
}

func TestTrustRefusesBadMaterial(t *testing.T) {
	p := newPKI(t)
	m := p.material(nil)
	tr, err := NewTrust(m)
	if err != nil {
		t.Fatal(err)
	}
	if tr.cfg.MinVersion != tls.VersionTLS13 || tr.cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("weak TLS config: %+v", tr.cfg)
	}
	m.CAs = map[string][]byte{"default": []byte("junk")}
	if _, err := NewTrust(m); err == nil {
		t.Fatal("empty CA accepted")
	}
	leaf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.serverCert.Certificate[0]})
	m.CAs = map[string][]byte{"default": leaf}
	if _, err := NewTrust(m); err == nil || !strings.Contains(err.Error(), "not a CA") {
		t.Fatalf("leaf certificate accepted as CA: %v", err)
	}
	m.CAs = map[string][]byte{"a": p.ca.pem, "b": p.ca.pem}
	if _, err := NewTrust(m); err == nil {
		t.Fatal("one CA in two bundles accepted")
	}
}

func TestQoSGrant(t *testing.T) {
	b := &stub{}
	p, url := start(t, b, testClients)
	body := `{"queues":[],"rules":[]}`
	for _, who := range []string{"tf-prod", "reader"} {
		if resp, _ := do(t, client(p, who), "PUT", url+"/v1/qos", body, map[string]string{"If-Match": `"x"`}); resp.StatusCode != 403 {
			t.Fatalf("%s put qos: %d", who, resp.StatusCode)
		}
	}
	for _, who := range []string{"netops", "admin"} {
		if resp, _ := do(t, client(p, who), "PUT", url+"/v1/qos", body, map[string]string{"If-Match": `"x"`}); resp.StatusCode != 202 {
			t.Fatalf("%s put qos: %d", who, resp.StatusCode)
		}
	}
	if len(b.puts) != 2 || b.puts[0] != "netops:qos" || b.pre.IfMatch != "x" {
		t.Fatalf("backend got %v %+v", b.puts, b.pre)
	}
	if resp, _ := do(t, client(p, "netops"), "PUT", url+"/v1/qos", `{"queues":[],"bogus":1}`, nil); resp.StatusCode != 400 {
		t.Fatalf("unknown field: %d", resp.StatusCode)
	}
}

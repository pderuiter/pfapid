package api

import (
	"crypto/x509"
	"strings"
	"testing"
)

const healthz = "/v1/healthz"

func TestIdentityCAAndSPIFFE(t *testing.T) {
	p := newPKI(t)
	corp := newCA(t, "corp-root")
	clients := []Client{
		{Name: "tf-prod", CA: "default"},
		{Name: "ops", CA: "corp"},
		{Name: "ci", CA: "corp", SPIFFEID: "spiffe://corp.example/terraform/ci"},
	}
	srv, url := startWith(t, &stub{}, clients, p.material(map[string]*testCA{"corp": corp}))

	for _, tc := range []struct {
		what string
		ca   *testCA
		cn   string
		uri  string
		want int
		who  string
	}{
		{"CN from its own CA", p.ca, "tf-prod", "", 200, "tf-prod"},
		{"same CN from another CA", corp, "tf-prod", "", 403, ""},
		{"CN client of the corp CA", corp, "ops", "", 200, "ops"},
		{"corp CN presented via the default CA", p.ca, "ops", "", 403, ""},
		{"SPIFFE ID", corp, "anything", "spiffe://corp.example/terraform/ci", 200, "ci"},
		{"SPIFFE client by CN only", corp, "ci", "", 403, ""},
		{"SPIFFE ID from the wrong CA", p.ca, "x", "spiffe://corp.example/terraform/ci", 403, ""},
		{"unknown SPIFFE ID", corp, "y", "spiffe://corp.example/other", 403, ""},
	} {
		cert := tc.ca.issue(tc.cn, tc.uri, x509.ExtKeyUsageClientAuth)
		resp, body := do(t, httpClient(p, cert), "GET", url+healthz, "", nil)
		if resp == nil || resp.StatusCode != tc.want || (tc.who != "" && !strings.Contains(body, `"client":"`+tc.who+`"`)) {
			code := 0
			if resp != nil {
				code = resp.StatusCode
			}
			t.Errorf("%s: got %d %s, want %d %s", tc.what, code, body, tc.want, tc.who)
		}
	}

	// Rotation: drop the corp bundle -> refused while clients need it;
	// a new server certificate is served on the next handshake.
	next := newPKI(t)
	m := next.material(nil)
	m.CAs = map[string][]byte{"default": p.ca.pem}
	tr, err := NewTrust(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.SetTrust(tr); err == nil || !strings.Contains(err.Error(), "corp") {
		t.Fatalf("material without the corp bundle accepted: %v", err)
	}
	m.CAs["corp"] = corp.pem
	tr, _ = NewTrust(m)
	if err := srv.SetTrust(tr); err != nil {
		t.Fatal(err)
	}
	cert := p.ca.issue("tf-prod", "", x509.ExtKeyUsageClientAuth)
	if resp, _ := do(t, httpClient(p, cert), "GET", url+healthz, "", nil); resp != nil {
		t.Fatal("old server certificate still served after rotation")
	}
	if resp, _ := do(t, httpClient(next, cert), "GET", url+healthz, "", nil); resp == nil || resp.StatusCode != 200 {
		t.Fatal("new server certificate not served")
	}
}

func TestClientConfigChecks(t *testing.T) {
	p := newPKI(t)
	corp := newCA(t, "corp-root")
	two, _ := NewTrust(p.material(map[string]*testCA{"corp": corp}))
	for what, c := range map[string]Client{
		"ca required with two bundles": {Name: "x"},
		"unknown ca":                   {Name: "x", CA: "nope"},
		"bad spiffe id":                {Name: "x", CA: "corp", SPIFFEID: "spiffe://Corp.example/x?y=1"},
		"bad name":                     {Name: "a b", CA: "corp"},
	} {
		if _, err := New(&stub{}, []Client{c}, two, 1, 1, nil); err == nil {
			t.Errorf("%s: accepted", what)
		}
	}
	if _, err := New(&stub{}, []Client{{Name: "a", CA: "corp"}, {Name: "a", CA: "default"}}, two, 1, 1, nil); err == nil {
		t.Error("duplicate name accepted")
	}
	for _, ok := range []string{"spiffe://corp.example/terraform/ci", "spiffe://td/a/b"} {
		if !ValidSPIFFEID(ok) {
			t.Errorf("%s rejected", ok)
		}
	}
}

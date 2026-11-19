package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "pfapid.json")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// The shipped example must always load: it is what operators start from.
func TestExampleLoads(t *testing.T) {
	c, err := Load("../../deploy/pfapid.json.example")
	if err != nil {
		t.Fatal(err)
	}
	if c.User != "_pfapid" || c.Pfctl != "/sbin/pfctl" || c.StateDir != "/var/db/pfapid" {
		t.Fatalf("defaults not applied: %+v", c)
	}
	if c.ConfirmTimeout.Duration != 60*time.Second || c.TLS.ReloadInterval.Duration != time.Minute {
		t.Fatalf("durations: %v %v", c.ConfirmTimeout, c.TLS.ReloadInterval)
	}
	b := c.TLS.CABundles()
	if len(b) != 2 || b["pfapid"] == "" || b["corp"] == "" {
		t.Fatalf("bundles: %v", b)
	}
	if len(c.Clients) == 0 || len(c.Policy.Interfaces) == 0 {
		t.Fatalf("clients/policy missing: %+v", c)
	}
}

const minimal = `{
  "listen": "192.0.2.1:8443",
  "tls": {"cert": "/c", "key": "/k", %s},
  "policy": {"interfaces": ["frontend"]},
  "clients": [{"name": "tf"}]
}`

func cfg(tlsExtra string) string { return strings.Replace(minimal, "%s", tlsExtra, 1) }

func TestLegacyClientCA(t *testing.T) {
	c, err := Load(write(t, cfg(`"client_ca": "/ca.crt", "reload_interval": "0s"`)))
	if err != nil {
		t.Fatal(err)
	}
	if b := c.TLS.CABundles(); len(b) != 1 || b["default"] != "/ca.crt" {
		t.Fatalf("legacy client_ca: %v", b)
	}
	if c.TLS.ReloadInterval.Duration != 0 {
		t.Fatalf("reload 0 (off) not kept: %v", c.TLS.ReloadInterval)
	}
}

func TestValidationErrors(t *testing.T) {
	cases := map[string]struct{ body, want string }{
		"no listen":         {strings.Replace(cfg(`"client_ca": "/ca"`), `"listen": "192.0.2.1:8443",`, "", 1), "listen is required"},
		"no cert":           {strings.Replace(cfg(`"client_ca": "/ca"`), `"cert": "/c", `, "", 1), "tls.cert and tls.key"},
		"both CAs":          {cfg(`"client_ca": "/ca", "client_cas": {"a": "/a"}`), "not both"},
		"no CA":             {cfg(`"reload_interval": "1m"`), "tls.client_cas (or tls.client_ca) is required"},
		"bad bundle name":   {cfg(`"client_cas": {"Bad Name": "/a"}`), `bundle "Bad Name"`},
		"empty bundle path": {cfg(`"client_cas": {"corp": ""}`), `bundle "corp"`},
		"reload too short":  {cfg(`"client_ca": "/ca", "reload_interval": "5s"`), "reload_interval"},
		"reload too long":   {cfg(`"client_ca": "/ca", "reload_interval": "2h"`), "reload_interval"},
		"confirm too short": {strings.Replace(cfg(`"client_ca": "/ca"`), `"listen"`, `"confirm_timeout": "5s", "listen"`, 1), "confirm_timeout"},
		"confirm too long":  {strings.Replace(cfg(`"client_ca": "/ca"`), `"listen"`, `"confirm_timeout": "11m", "listen"`, 1), "confirm_timeout"},
		"no clients":        {strings.Replace(cfg(`"client_ca": "/ca"`), `[{"name": "tf"}]`, `[]`, 1), "at least one client"},
		"mgmt in policy":    {strings.Replace(cfg(`"client_ca": "/ca"`), `["frontend"]`, `["mgmt"]`, 1), "mgmt"},
	}
	for name, tc := range cases {
		_, err := Load(write(t, tc.body))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want error containing %q, got %v", name, tc.want, err)
		}
	}
}

func TestLoadErrors(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "missing.json")); !os.IsNotExist(err) {
		t.Fatalf("missing file: %v", err)
	}
	p := write(t, `{"listen": 1}`)
	if _, err := Load(p); err == nil || !strings.Contains(err.Error(), p) {
		t.Fatalf("bad JSON error should name the file: %v", err)
	}
	if _, err := Load(write(t, cfg(`"client_ca": "/ca", "reload_interval": "soon"`))); err == nil {
		t.Fatal("bad duration accepted")
	}
}

func TestDurationUnmarshal(t *testing.T) {
	var d Duration
	if err := json.Unmarshal([]byte(`"90s"`), &d); err != nil || d.Duration != 90*time.Second {
		t.Fatalf("90s: %v %v", d, err)
	}
	if err := json.Unmarshal([]byte(`90`), &d); err == nil {
		t.Fatal("a bare number must be refused (unit ambiguity)")
	}
	if err := json.Unmarshal([]byte(`"ninety"`), &d); err == nil {
		t.Fatal("bad duration accepted")
	}
}

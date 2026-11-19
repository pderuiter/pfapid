package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pderuiter/pfapid/internal/api"
	"github.com/pderuiter/pfapid/internal/pki"
)

func mustPKI(t *testing.T, args ...string) {
	t.Helper()
	if err := runPKI(args, io.Discard); err != nil {
		t.Fatalf("pki %v: %v", args, err)
	}
}

func material(t *testing.T, dir string) api.Material {
	t.Helper()
	rd := func(n string) []byte {
		b, err := os.ReadFile(filepath.Join(dir, n))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	return api.Material{CertPEM: rd("server.crt"), KeyPEM: rd("server.key"), CAs: map[string][]byte{"pfapid": rd("ca.crt")}}
}

func verifyClient(t *testing.T, crt string, roots *x509.CertPool) *x509.Certificate {
	t.Helper()
	b, _ := os.ReadFile(crt)
	var certs []*x509.Certificate
	for rest := b; ; {
		c, r, ok := cutCert(rest)
		if !ok {
			break
		}
		certs, rest = append(certs, c), r
	}
	inter := x509.NewCertPool()
	for _, c := range certs[1:] {
		inter.AddCert(c)
	}
	if _, err := certs[0].Verify(x509.VerifyOptions{Roots: roots, Intermediates: inter,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("%s does not verify: %v", crt, err)
	}
	return certs[0]
}

func TestPKISelfSigned(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "pki")
	mustPKI(t, "init", "-dir", dir, "-dns", "fw.example", "-ip", "192.0.2.1")
	for n, want := range map[string]os.FileMode{"ca.key": 0o600, "server.key": 0o600, "ca.crt": 0o644} {
		st, err := os.Stat(filepath.Join(dir, n))
		if err != nil || st.Mode().Perm() != want {
			t.Fatalf("%s: %v %v", n, st.Mode(), err)
		}
	}
	tr, err := api.NewTrust(material(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	if err := runPKI([]string{"init", "-dir", dir, "-dns", "fw.example"}, io.Discard); err == nil {
		t.Fatal("init overwrote an existing PKI")
	}

	out := filepath.Join(t.TempDir(), "ci")
	mustPKI(t, "issue", "-dir", dir, "-name", "ci", "-spiffe-id", "spiffe://corp.example/tf/ci", "-out", out)
	roots := x509.NewCertPool()
	ca, _ := readCert(filepath.Join(dir, "ca.crt"))
	roots.AddCert(ca)
	c := verifyClient(t, out+".crt", roots)
	if c.Subject.CommonName != "ci" || len(c.URIs) != 1 || c.URIs[0].String() != "spiffe://corp.example/tf/ci" {
		t.Fatalf("client cert %v %v", c.Subject, c.URIs)
	}
	if time.Until(c.NotAfter) > pki.ClientValidity+time.Hour {
		t.Fatal("client validity too long")
	}
	if err := runPKI([]string{"issue", "-dir", dir, "-name", "x", "-spiffe-id", "https://x/y", "-out", out + "2"}, io.Discard); err == nil {
		t.Fatal("non-SPIFFE URI accepted")
	}

	before := tr.NotAfter
	old, _ := readCert(filepath.Join(dir, "server.crt"))
	mustPKI(t, "renew", "-dir", dir, "-days", "30")
	tr2, err := api.NewTrust(material(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	renewed, _ := readCert(filepath.Join(dir, "server.crt"))
	if renewed.SerialNumber.Cmp(old.SerialNumber) == 0 || !tr2.NotAfter.Before(before) ||
		renewed.DNSNames[0] != "fw.example" || !renewed.IPAddresses[0].Equal(old.IPAddresses[0]) {
		t.Fatalf("renew: %v %v", renewed.DNSNames, renewed.IPAddresses)
	}
}

// A company root with an intermediate: pfapid signs with the intermediate,
// the firewall never sees the root key, and clients chain to the root.
func TestPKIBringYourOwnCA(t *testing.T) {
	now := time.Now()
	// A company root (no path length limit; pki.NewCA's pathlen 0 would
	// forbid the intermediate).
	rk, _ := pki.NewCA("throwaway", now)
	rtmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Corp Root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(20 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rder, err := x509.CreateCertificate(rand.Reader, rtmpl, rtmpl, rk.Key.Public(), rk.Key)
	if err != nil {
		t.Fatal(err)
	}
	rc, _ := x509.ParseCertificate(rder)
	root := &pki.CA{Cert: rc, Key: rk.Key}
	ik, _ := pki.NewCA("throwaway", now) // just for a key
	sn, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	tmpl := &x509.Certificate{SerialNumber: sn, Subject: pkix.Name{CommonName: "Corp Network Intermediate"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(5 * 365 * 24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, MaxPathLenZero: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, root.Cert, ik.Key.Public(), root.Key)
	if err != nil {
		t.Fatal(err)
	}
	inter, _ := x509.ParseCertificate(der)
	src := t.TempDir()
	kp, _ := pki.KeyPEM(ik.Key)
	_ = os.WriteFile(filepath.Join(src, "int.key"), kp, 0o600)
	_ = os.WriteFile(filepath.Join(src, "int.crt"), pki.CertPEM(inter), 0o600)
	_ = os.WriteFile(filepath.Join(src, "root.key"), func() []byte { b, _ := pki.KeyPEM(root.Key); return b }(), 0o600)

	if err := runPKI([]string{"init", "-dir", t.TempDir(), "-dns", "fw", "-ca-cert", filepath.Join(src, "int.crt"),
		"-ca-key", filepath.Join(src, "root.key")}, io.Discard); err == nil || !strings.Contains(err.Error(), "does not belong") {
		t.Fatalf("mismatched CA key accepted: %v", err)
	}
	dir := filepath.Join(t.TempDir(), "pki")
	byo := []string{"-ca-cert", filepath.Join(src, "int.crt"), "-ca-key", filepath.Join(src, "int.key")}
	mustPKI(t, append([]string{"init", "-dir", dir, "-dns", "fw.corp.example"}, byo...)...)
	if _, err := os.Stat(filepath.Join(dir, "ca.key")); !os.IsNotExist(err) {
		t.Fatal("the company CA key was copied into the pfapid directory")
	}
	out := filepath.Join(t.TempDir(), "ops")
	mustPKI(t, append([]string{"issue", "-name", "ops", "-out", out}, byo...)...)
	roots := x509.NewCertPool()
	roots.AddCert(root.Cert)
	verifyClient(t, out+".crt", roots)
	// The server chain includes the intermediate.
	m := material(t, dir)
	if strings.Count(string(m.CertPEM), "BEGIN CERTIFICATE") != 2 {
		t.Fatal("server.crt lacks the intermediate")
	}
	if _, err := api.NewTrust(m); err != nil {
		t.Fatal(err)
	}
}

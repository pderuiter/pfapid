package pki

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var now = time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)

func TestCAAndLeaves(t *testing.T) {
	ca, err := NewCA("test CA", now)
	if err != nil {
		t.Fatal(err)
	}
	if !ca.Cert.IsCA || !ca.Cert.MaxPathLenZero || ca.Cert.MaxPathLen != 0 ||
		ca.Cert.NotAfter.Sub(now) != CAValidity || ca.Cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Fatalf("CA: %+v", ca.Cert)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)

	srv, _, err := ca.Issue(LeafSpec{CN: "fw", Server: true, DNS: []string{"fw.example.net"}, IPs: []net.IP{net.ParseIP("192.0.2.1")}, Validity: ServerValidity}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := srv.Verify(x509.VerifyOptions{Roots: pool, DNSName: "fw.example.net", CurrentTime: now}); err != nil {
		t.Fatalf("server cert does not verify: %v", err)
	}
	if srv.IsCA || srv.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || srv.NotAfter.Sub(now) != ServerValidity {
		t.Fatalf("server cert: %+v", srv)
	}

	cl, key, err := ca.Issue(LeafSpec{CN: "ci", SPIFFEID: "spiffe://example.net/ci", Validity: ClientValidity}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cl.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, CurrentTime: now}); err != nil {
		t.Fatalf("client cert does not verify: %v", err)
	}
	if len(cl.URIs) != 1 || cl.URIs[0].String() != "spiffe://example.net/ci" || !key.PublicKey.Equal(cl.PublicKey) {
		t.Fatalf("client cert: %v", cl.URIs)
	}

	// A leaf never outlives its issuer.
	long, _, err := ca.Issue(LeafSpec{CN: "x", Validity: 2 * CAValidity}, now)
	if err != nil || !long.NotAfter.Equal(ca.Cert.NotAfter) {
		t.Fatalf("leaf outlives CA: %v %v", long.NotAfter, err)
	}

	for name, s := range map[string]LeafSpec{
		"empty CN":           {Validity: time.Hour},
		"server without SAN": {CN: "fw", Server: true, Validity: time.Hour},
		"bad spiffe":         {CN: "c", SPIFFEID: "https://example.net/x", Validity: time.Hour},
		"unparsable spiffe":  {CN: "c", SPIFFEID: "spiffe://%zz", Validity: time.Hour},
	} {
		if _, _, err := ca.Issue(s, now); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestPEMAndLoadCA(t *testing.T) {
	dir := t.TempDir()
	ca, err := NewCA("ca", now)
	if err != nil {
		t.Fatal(err)
	}
	kp, err := KeyPEM(ca.Key)
	if err != nil {
		t.Fatal(err)
	}
	certF, keyF := filepath.Join(dir, "ca.crt"), filepath.Join(dir, "ca.key")
	if err := WriteNew(certF, CertPEM(ca.Cert), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := WriteNew(keyF, kp, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadCA(certF, keyF)
	if err != nil || !got.Cert.Equal(ca.Cert) {
		t.Fatalf("LoadCA: %v", err)
	}

	// EC (SEC 1) and RSA PKCS#1 keys are accepted too.
	ecDER, _ := x509.MarshalECPrivateKey(ca.Key.(*ecdsa.PrivateKey))
	ecF := writeFile(t, dir, "ec.key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: ecDER}))
	if _, err := LoadCA(certF, ecF); err != nil {
		t.Fatalf("EC key: %v", err)
	}
	rsaCert, rsaKey := rsaCA(t)
	rsaCertF := writeFile(t, dir, "rsa.crt", CertPEM(rsaCert))
	rsaKeyF := writeFile(t, dir, "rsa.key", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rsaKey)}))
	rca, err := LoadCA(rsaCertF, rsaKeyF)
	if err != nil {
		t.Fatalf("RSA CA: %v", err)
	}
	if _, _, err := rca.Issue(LeafSpec{CN: "c", Validity: time.Hour}, time.Now()); err != nil {
		t.Fatalf("issue with RSA CA: %v", err)
	}

	other, _ := NewCA("other", now)
	otherKey, _ := KeyPEM(other.Key)
	leaf, _, _ := ca.Issue(LeafSpec{CN: "leaf", Validity: time.Hour}, now)
	cases := map[string][2]string{
		"missing cert":    {filepath.Join(dir, "nope"), keyF},
		"missing key":     {certF, filepath.Join(dir, "nope")},
		"not PEM cert":    {writeFile(t, dir, "junk.crt", []byte("junk")), keyF},
		"bad DER cert":    {writeFile(t, dir, "bad.crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1, 2}})), keyF},
		"leaf as CA":      {writeFile(t, dir, "leaf.crt", CertPEM(leaf)), keyF},
		"not PEM key":     {certF, writeFile(t, dir, "junk.key", []byte("junk"))},
		"bad DER key":     {certF, writeFile(t, dir, "bad.key", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1}}))},
		"unsupported key": {certF, writeFile(t, dir, "dsa.key", pem.EncodeToMemory(&pem.Block{Type: "DSA PRIVATE KEY", Bytes: []byte{1}}))},
		"encrypted key": {certF, writeFile(t, dir, "enc.key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY",
			Headers: map[string]string{"Proc-Type": "4,ENCRYPTED", "DEK-Info": "AES-256-CBC,00112233445566778899AABBCCDDEEFF"}, Bytes: []byte{1}}))},
		"key of another CA": {certF, writeFile(t, dir, "other.key", otherKey)},
	}
	for name, c := range cases {
		if _, err := LoadCA(c[0], c[1]); err == nil {
			t.Errorf("%s: accepted", name)
		} else if name == "encrypted key" && !strings.Contains(err.Error(), "encrypted") {
			t.Errorf("encrypted key: %v", err)
		}
	}
}

func rsaCA(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "rsa"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return c, k
}

func writeFile(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestWriteNewAndReplace(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "server.key")
	if err := WriteNew(p, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteNew(p, []byte("two"), 0o600); !os.IsExist(err) {
		t.Fatalf("WriteNew overwrote an existing file: %v", err)
	}
	if err := Replace(p, []byte("three"), 0o600); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	fi, _ := os.Stat(p)
	if string(b) != "three" || fi.Mode().Perm() != 0o600 {
		t.Fatalf("replace: %q %v", b, fi.Mode())
	}
	// A stale .new file from an interrupted run does not block Replace.
	_ = os.WriteFile(p+".new", []byte("stale"), 0o600)
	if err := Replace(p, []byte("four"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(p + ".new"); !os.IsNotExist(err) {
		t.Fatalf("temp file left: %v", err)
	}
	if err := Replace(filepath.Join(dir, "missing", "f"), nil, 0o600); err == nil {
		t.Fatal("replace into a missing directory succeeded")
	}
	if _, err := KeyPEM(nil); err == nil {
		t.Fatal("KeyPEM(nil) succeeded")
	}
}

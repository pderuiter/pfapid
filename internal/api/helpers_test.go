package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/pderuiter/pfapid/internal/priv"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  []byte
	next int64
}

func newCA(t *testing.T, cn string) *testCA {
	t.Helper()
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	c, _ := x509.ParseCertificate(der)
	return &testCA{cert: c, key: k, pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), next: 10}
}

// issue makes a leaf; uri, if set, becomes the single URI SAN.
func (ca *testCA) issue(cn, uri string, eku x509.ExtKeyUsage) tls.Certificate {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ca.next++
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(ca.next), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{eku}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	if uri != "" {
		u, _ := url.Parse(uri)
		tmpl.URIs = []*url.URL{u}
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &k.PublicKey, ca.key)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: k}
}

type pki struct {
	ca         *testCA
	serverCert tls.Certificate
	clients    map[string]tls.Certificate
	pool       *x509.CertPool // to verify the server
}

func newPKI(t *testing.T, names ...string) *pki {
	t.Helper()
	ca := newCA(t, "test-ca")
	p := &pki{ca: ca, serverCert: ca.issue("pfapid", "", x509.ExtKeyUsageServerAuth), clients: map[string]tls.Certificate{}, pool: x509.NewCertPool()}
	p.pool.AddCert(ca.cert)
	for _, n := range names {
		p.clients[n] = ca.issue(n, "", x509.ExtKeyUsageClientAuth)
	}
	return p
}

// material is the server's TLS material: bundle "default" is this pki's CA,
// extra adds more bundles.
func (p *pki) material(extra map[string]*testCA) Material {
	keyDER, _ := x509.MarshalECPrivateKey(p.serverCert.PrivateKey.(*ecdsa.PrivateKey))
	m := Material{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: p.serverCert.Certificate[0]}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		CAs:     map[string][]byte{"default": p.ca.pem},
	}
	for n, ca := range extra {
		m.CAs[n] = ca.pem
	}
	return m
}

func startWith(t *testing.T, b priv.Backend, clients []Client, m Material) (*Server, string) {
	t.Helper()
	tr, err := NewTrust(m)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(b, clients, tr, 1000, 1000, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewUnstartedServer(s.Handler())
	ts.TLS = s.TLSConfig()
	ts.StartTLS()
	t.Cleanup(ts.Close)
	return s, ts.URL
}

func start(t *testing.T, b priv.Backend, clients []Client) (*pki, string) {
	t.Helper()
	p := newPKI(t, "tf-prod", "reader", "admin", "netops", "stranger")
	_, url := startWith(t, b, clients, p.material(nil))
	return p, url
}

func httpClient(p *pki, certs ...tls.Certificate) *http.Client {
	tc := &tls.Config{RootCAs: p.pool, MinVersion: tls.VersionTLS13, Certificates: certs}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: tc}, Timeout: 5 * time.Second}
}

func client(p *pki, name string) *http.Client {
	if c, ok := p.clients[name]; ok {
		return httpClient(p, c)
	}
	return httpClient(p)
}

package api

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"time"
)

// Material is the TLS material the privileged process reads from disk and
// hands to the network process: the server certificate and key, and one or
// more named CA bundles that may issue client certificates (for example the
// self-signed pfapid CA and a company CA).
type Material struct {
	CertPEM []byte            `json:"cert_pem"`
	KeyPEM  []byte            `json:"key_pem"`
	CAs     map[string][]byte `json:"cas"`
}

// Trust is a parsed Material: the server TLS configuration plus, for every
// CA certificate, the name of the bundle it came from. It is replaced as a
// whole when the files change.
type Trust struct {
	cfg      *tls.Config
	bundleOf map[[32]byte]string
	names    []string
	NotAfter time.Time // server certificate expiry
}

// NewTrust builds the server configuration: TLS 1.3 only, a client
// certificate is required and must chain to one of the bundles.
func NewTrust(m Material) (*Trust, error) {
	cert, err := tls.X509KeyPair(m.CertPEM, m.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("server certificate: %w", err)
	}
	if len(m.CAs) == 0 {
		return nil, errors.New("no client CA bundle")
	}
	t := &Trust{bundleOf: map[[32]byte]string{}}
	pool := x509.NewCertPool()
	for name, b := range m.CAs {
		if err := t.addBundle(pool, name, b); err != nil {
			return nil, err
		}
	}
	sort.Strings(t.names)
	if leaf, err := x509.ParseCertificate(cert.Certificate[0]); err == nil {
		t.NotAfter = leaf.NotAfter
	}
	t.cfg = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    pool,
	}
	return t, nil
}

// addBundle adds every CA certificate of bundle name to the pool and
// records which bundle it belongs to.
func (t *Trust) addBundle(pool *x509.CertPool, name string, b []byte) error {
	n := 0
	for rest := b; ; {
		var blk *pem.Block
		blk, rest = pem.Decode(rest)
		if blk == nil {
			break
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		if err := t.addCA(pool, name, blk.Bytes); err != nil {
			return err
		}
		n++
	}
	if n == 0 {
		return fmt.Errorf("client CA %s: no certificates found", name)
	}
	t.names = append(t.names, name)
	return nil
}

func (t *Trust) addCA(pool *x509.CertPool, name string, der []byte) error {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("client CA %s: %w", name, err)
	}
	if !c.IsCA {
		return fmt.Errorf("client CA %s: %q is not a CA certificate", name, c.Subject.CommonName)
	}
	fp := sha256.Sum256(c.Raw)
	if other, dup := t.bundleOf[fp]; dup && other != name {
		return fmt.Errorf("client CA %q is in both bundle %s and %s", c.Subject.CommonName, other, name)
	}
	t.bundleOf[fp] = name
	pool.AddCert(c)
	return nil
}

// Bundles returns the bundle names, sorted.
func (t *Trust) Bundles() []string { return t.names }

// anchors returns, for each verified chain, the bundle its trust anchor
// (the last certificate) belongs to.
func (t *Trust) anchors(chains [][]*x509.Certificate) []string {
	var out []string
	for _, ch := range chains {
		if len(ch) == 0 {
			continue
		}
		if name, ok := t.bundleOf[sha256.Sum256(ch[len(ch)-1].Raw)]; ok {
			out = append(out, name)
		}
	}
	return out
}

// spiffeID returns the certificate's SPIFFE ID. An X509-SVID carries exactly
// one URI SAN; anything else is not treated as a SPIFFE identity.
func spiffeID(c *x509.Certificate) string {
	if len(c.URIs) != 1 || c.URIs[0].Scheme != "spiffe" {
		return ""
	}
	return c.URIs[0].String()
}

// ValidSPIFFEID checks the form spiffe://trust-domain/path (spec: lower case
// trust domain, a path, no query, fragment, port or user info).
func ValidSPIFFEID(s string) bool {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "spiffe" || u.Host == "" || u.Port() != "" || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || u.Path == "" || u.Path == "/" || u.String() != s {
		return false
	}
	for _, r := range u.Host {
		lower := r >= 'a' && r <= 'z'
		digit := r >= '0' && r <= '9'
		if !lower && !digit && r != '.' && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

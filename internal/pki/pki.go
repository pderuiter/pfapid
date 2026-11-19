// Package pki is pfapid's built-in certificate authority: the default way
// to get going without an existing PKI. It makes a self-signed CA (or uses
// an existing company CA/intermediate), a server certificate, and client
// certificates identified by CN and optionally a SPIFFE ID (URI SAN).
//
// Keys are ECDSA P-256. Files are written with O_EXCL, so nothing is ever
// silently overwritten; private keys are 0600 and never printed.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

const (
	CAValidity     = 10 * 365 * 24 * time.Hour
	ServerValidity = 397 * 24 * time.Hour
	ClientValidity = 90 * 24 * time.Hour
)

// CA is a certificate plus the key that signs with it.
type CA struct {
	Cert *x509.Certificate
	Key  crypto.Signer
}

func serial() (*big.Int, error) {
	return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
}

func newKey() (*ecdsa.PrivateKey, error) { return ecdsa.GenerateKey(elliptic.P256(), rand.Reader) }

// NewCA makes a self-signed root, constrained to issue leaves only.
func NewCA(cn string, now time.Time) (*CA, error) {
	k, err := newKey()
	if err != nil {
		return nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn, Subject: pkix.Name{CommonName: cn},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: now.Add(CAValidity),
		IsCA: true, BasicConstraintsValid: true, MaxPathLen: 0, MaxPathLenZero: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		return nil, err
	}
	c, err := x509.ParseCertificate(der)
	return &CA{Cert: c, Key: k}, err
}

// LeafSpec describes a server or client certificate.
type LeafSpec struct {
	CN       string
	Server   bool // server (DNS/IP SANs) or client certificate
	DNS      []string
	IPs      []net.IP
	SPIFFEID string // client only: becomes the single URI SAN
	Validity time.Duration
}

// Issue signs a new key pair. It returns the certificate and the key.
func (ca *CA) Issue(s LeafSpec, now time.Time) (*x509.Certificate, *ecdsa.PrivateKey, error) {
	if s.CN == "" {
		return nil, nil, errors.New("pki: empty CN")
	}
	k, err := newKey()
	if err != nil {
		return nil, nil, err
	}
	sn, err := serial()
	if err != nil {
		return nil, nil, err
	}
	notAfter := now.Add(s.Validity)
	if notAfter.After(ca.Cert.NotAfter) {
		notAfter = ca.Cert.NotAfter // never outlive the issuer
	}
	tmpl := &x509.Certificate{
		SerialNumber: sn, Subject: pkix.Name{CommonName: s.CN},
		NotBefore: now.Add(-5 * time.Minute), NotAfter: notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	if s.Server {
		if len(s.DNS) == 0 && len(s.IPs) == 0 {
			return nil, nil, errors.New("pki: a server certificate needs at least one DNS name or IP")
		}
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		tmpl.DNSNames, tmpl.IPAddresses = s.DNS, s.IPs
	} else {
		tmpl.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		if s.SPIFFEID != "" {
			u, err := url.Parse(s.SPIFFEID)
			if err != nil || u.Scheme != "spiffe" {
				return nil, nil, fmt.Errorf("pki: spiffe id %q", s.SPIFFEID)
			}
			tmpl.URIs = []*url.URL{u}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, &k.PublicKey, ca.Key)
	if err != nil {
		return nil, nil, err
	}
	c, err := x509.ParseCertificate(der)
	return c, k, err
}

// CertPEM and KeyPEM encode for files.
func CertPEM(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func KeyPEM(k crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// LoadCA reads an existing CA certificate and its key (PKCS#8, EC or RSA
// PKCS#1, unencrypted). The key must match the certificate, and the
// certificate must be allowed to sign certificates.
func LoadCA(certFile, keyFile string) (*CA, error) {
	cb, err := os.ReadFile(certFile) // #nosec G304 -- operator-supplied path
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(cb)
	if blk == nil || blk.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("%s: no PEM certificate", certFile)
	}
	c, err := x509.ParseCertificate(blk.Bytes)
	if err != nil {
		return nil, err
	}
	if !c.IsCA || c.KeyUsage&x509.KeyUsageCertSign == 0 {
		return nil, fmt.Errorf("%s: %q is not a CA that may sign certificates", certFile, c.Subject.CommonName)
	}
	kb, err := os.ReadFile(keyFile) // #nosec G304 -- operator-supplied path
	if err != nil {
		return nil, err
	}
	defer clear(kb)
	kblk, _ := pem.Decode(kb)
	if kblk == nil {
		return nil, fmt.Errorf("%s: no PEM key", keyFile)
	}
	if x509.IsEncryptedPEMBlock(kblk) { //nolint:staticcheck // detect only, never decrypt legacy PEM
		return nil, fmt.Errorf("%s: encrypted keys are not supported; decrypt to a 0600 file first", keyFile)
	}
	var key any
	switch kblk.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(kblk.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(kblk.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(kblk.Bytes)
	default:
		return nil, fmt.Errorf("%s: unsupported key type %q", keyFile, kblk.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", keyFile, err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("%s: not a signing key", keyFile)
	}
	type eq interface{ Equal(crypto.PublicKey) bool }
	if pk, ok := signer.Public().(eq); !ok || !pk.Equal(c.PublicKey) {
		return nil, fmt.Errorf("%s does not belong to %s", keyFile, certFile)
	}
	return &CA{Cert: c, Key: signer}, nil
}

// WriteNew writes a file that must not exist yet.
func WriteNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// Replace atomically replaces a file (write temp + rename), so the
// certificate reload never sees a half-written file.
func Replace(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".new"
	_ = os.Remove(tmp)
	if err := WriteNew(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

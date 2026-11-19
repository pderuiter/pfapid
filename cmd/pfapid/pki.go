package main

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pderuiter/pfapid/internal/api"
	"github.com/pderuiter/pfapid/internal/pki"
)

type listFlag []string

func (l *listFlag) String() string     { return strings.Join(*l, ",") }
func (l *listFlag) Set(s string) error { *l = append(*l, s); return nil }

var errUsage = errors.New("usage: pfapid pki init|issue|renew (see pfapid pki help)")

const pkiUsage = `usage:
  pfapid pki init  [-dir D] -dns NAME [-dns ...] [-ip ADDR ...] [-ca-cert F -ca-key F]
      Self-signed (default): creates D/ca.crt, D/ca.key, D/server.crt, D/server.key.
      With -ca-cert/-ca-key: signs the server certificate with your existing CA
      or intermediate; its key is NOT copied into D.
  pfapid pki issue [-dir D] -name CN [-spiffe-id spiffe://td/path] [-days N] -out PREFIX [-ca-cert F -ca-key F]
      Client certificate: PREFIX.crt and PREFIX.key (0600).
  pfapid pki renew [-dir D] [-days N] [-ca-cert F -ca-key F]
      New server key and certificate with the same names; a running pfapid
      picks it up within tls.reload_interval.
`

const (
	caCertFile = "ca.crt"
	caKeyFile  = "ca.key"
)

// pkiOpts are the parsed flags of a pki subcommand.
type pkiOpts struct {
	dir, caCert, caKey string
	dns, ips           listFlag
	name, spiffe, out  string
	days               int
	now                time.Time
	stdout             io.Writer
}

func runPKI(args []string, stdout io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" {
		_, _ = io.WriteString(stdout, pkiUsage)
		if len(args) == 0 {
			return errUsage
		}
		return nil
	}
	o, err := parsePKIFlags(args, stdout)
	if err != nil {
		return err
	}
	switch args[0] {
	case "init":
		return o.init()
	case "renew":
		return o.renew()
	case "issue":
		return o.issue()
	}
	return errUsage
}

func parsePKIFlags(args []string, stdout io.Writer) (*pkiOpts, error) {
	o := &pkiOpts{stdout: stdout}
	fs := flag.NewFlagSet("pki "+args[0], flag.ContinueOnError)
	fs.StringVar(&o.dir, "dir", "/etc/pfapid/pki", "PKI directory")
	fs.StringVar(&o.caCert, "ca-cert", "", "existing CA certificate (PEM) to sign with instead of D/ca.crt")
	fs.StringVar(&o.caKey, "ca-key", "", "key of -ca-cert")
	fs.Var(&o.dns, "dns", "server DNS name (repeatable)")
	fs.Var(&o.ips, "ip", "server IP address (repeatable)")
	fs.StringVar(&o.name, "name", "", "client name: the certificate CN and the clients[].name in pfapid.json")
	fs.StringVar(&o.spiffe, "spiffe-id", "", "client SPIFFE ID (URI SAN)")
	fs.IntVar(&o.days, "days", 0, "validity in days (default: server 397, client 90)")
	fs.StringVar(&o.out, "out", "", "output prefix for the client certificate and key")
	if err := fs.Parse(args[1:]); err != nil {
		return nil, err
	}
	if (o.caCert == "") != (o.caKey == "") {
		return nil, errors.New("-ca-cert and -ca-key go together")
	}
	if o.days < 0 || o.days > 3650 {
		return nil, errors.New("-days must be 1..3650")
	}
	o.now = time.Now()
	return o, nil
}

func (o *pkiOpts) loadCA() (*pki.CA, error) {
	if o.caCert != "" {
		return pki.LoadCA(o.caCert, o.caKey)
	}
	return pki.LoadCA(filepath.Join(o.dir, caCertFile), filepath.Join(o.dir, caKeyFile))
}

func (o *pkiOpts) validity(def time.Duration) time.Duration {
	if o.days > 0 {
		return time.Duration(o.days) * 24 * time.Hour
	}
	return def
}

func (o *pkiOpts) init() error {
	var addrs []net.IP
	for _, s := range o.ips {
		ip := net.ParseIP(s)
		if ip == nil {
			return fmt.Errorf("-ip %q", s)
		}
		addrs = append(addrs, ip)
	}
	if len(o.dns) == 0 && len(addrs) == 0 {
		return errors.New("give the firewall's -dns name(s) and/or -ip address(es)")
	}
	if err := os.MkdirAll(o.dir, 0o700); err != nil { // #nosec G703 -- operator-supplied directory
		return err
	}
	var ca *pki.CA
	var err error
	if o.caCert != "" {
		ca, err = o.adoptCA()
	} else {
		ca, err = o.newCA(firstOf(o.dns, addrs))
	}
	if err != nil {
		return err
	}
	return writeServer(o.dir, ca, pki.LeafSpec{CN: firstOf(o.dns, addrs), Server: true, DNS: o.dns, IPs: addrs,
		Validity: o.validity(pki.ServerValidity)}, o.now, false, o.stdout)
}

// adoptCA loads the operator's CA and keeps its certificate for the client
// bundle and the server chain; its key is not copied.
func (o *pkiOpts) adoptCA() (*pki.CA, error) {
	ca, err := o.loadCA()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(o.caCert) // #nosec G304 G703 -- operator-supplied path
	if err != nil {
		return nil, err
	}
	if err := pki.WriteNew(filepath.Join(o.dir, caCertFile), b, 0o644); err != nil { // #nosec G703 -- operator-supplied directory
		return nil, err
	}
	return ca, nil
}

// newCA creates the self-signed pfapid CA in the PKI directory.
func (o *pkiOpts) newCA(subject string) (*pki.CA, error) {
	ca, err := pki.NewCA("pfapid CA "+subject, o.now)
	if err != nil {
		return nil, err
	}
	kp, err := pki.KeyPEM(ca.Key)
	if err != nil {
		return nil, err
	}
	if err := pki.WriteNew(filepath.Join(o.dir, caKeyFile), kp, 0o600); err != nil {
		return nil, err
	}
	if err := pki.WriteNew(filepath.Join(o.dir, caCertFile), pki.CertPEM(ca.Cert), 0o644); err != nil {
		return nil, err
	}
	return ca, nil
}

func (o *pkiOpts) renew() error {
	old, err := readCert(filepath.Join(o.dir, "server.crt"))
	if err != nil {
		return err
	}
	ca, err := o.loadCA()
	if err != nil {
		return err
	}
	return writeServer(o.dir, ca, pki.LeafSpec{CN: old.Subject.CommonName, Server: true, DNS: old.DNSNames,
		IPs: old.IPAddresses, Validity: o.validity(pki.ServerValidity)}, o.now, true, o.stdout)
}

func (o *pkiOpts) issue() error {
	if o.name == "" || o.out == "" {
		return errors.New("issue needs -name and -out")
	}
	if o.spiffe != "" && !api.ValidSPIFFEID(o.spiffe) {
		return fmt.Errorf("-spiffe-id %q is not spiffe://trust-domain/path", o.spiffe)
	}
	ca, err := o.loadCA()
	if err != nil {
		return err
	}
	c, k, err := ca.Issue(pki.LeafSpec{CN: o.name, SPIFFEID: o.spiffe, Validity: o.validity(pki.ClientValidity)}, o.now)
	if err != nil {
		return err
	}
	kp, err := pki.KeyPEM(k)
	if err != nil {
		return err
	}
	if err := pki.WriteNew(o.out+".key", kp, 0o600); err != nil {
		return err
	}
	if err := pki.WriteNew(o.out+".crt", chainPEM(c, ca), 0o644); err != nil {
		return err
	}
	id := "CN " + o.name
	if o.spiffe != "" {
		id = "SPIFFE ID " + o.spiffe
	}
	fmt.Fprintf(o.stdout, "issued %s.crt (%s, expires %s)\n", o.out, id, c.NotAfter.Format(time.DateOnly))
	return nil
}

func firstOf(dns []string, ips []net.IP) string {
	if len(dns) > 0 {
		return dns[0]
	}
	return ips[0].String()
}

// chainPEM is the leaf plus, when the issuer is an intermediate, the issuer,
// so peers that only trust the root can build the chain.
func chainPEM(c *x509.Certificate, ca *pki.CA) []byte {
	b := pki.CertPEM(c)
	if !isSelfSigned(ca.Cert) {
		b = append(b, pki.CertPEM(ca.Cert)...)
	}
	return b
}

func isSelfSigned(c *x509.Certificate) bool {
	return c.CheckSignatureFrom(c) == nil
}

func writeServer(dir string, ca *pki.CA, spec pki.LeafSpec, now time.Time, replace bool, stdout io.Writer) error {
	c, k, err := ca.Issue(spec, now)
	if err != nil {
		return err
	}
	kp, err := pki.KeyPEM(k)
	if err != nil {
		return err
	}
	defer clear(kp)
	write := pki.WriteNew
	if replace {
		write = pki.Replace
	}
	// Key first: a reload between the two writes fails the key/cert match
	// check and keeps the old material until the next interval.
	if err := write(filepath.Join(dir, "server.key"), kp, 0o600); err != nil {
		return err
	}
	if err := write(filepath.Join(dir, "server.crt"), chainPEM(c, ca), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "server certificate %s for %v %v, expires %s\n", spec.CN, spec.DNS, spec.IPs, c.NotAfter.Format(time.DateOnly))
	return nil
}

func readCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path) // #nosec G304 G703 -- operator-supplied path
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s: no PEM certificate", path)
	}
	return x509.ParseCertificate(blk.Bytes)
}

// cutCert decodes the first PEM certificate in b.
func cutCert(b []byte) (*x509.Certificate, []byte, bool) {
	for {
		blk, rest := pem.Decode(b)
		if blk == nil {
			return nil, nil, false
		}
		if blk.Type == "CERTIFICATE" {
			c, err := x509.ParseCertificate(blk.Bytes)
			return c, rest, err == nil
		}
		b = rest
	}
}

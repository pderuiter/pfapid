// Package config loads /etc/pfapid.json. The file is root-owned and read
// only by the privileged process; the network process receives what it
// needs over IPC.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/pderuiter/pfapid/internal/api"
	"github.com/pderuiter/pfapid/internal/model"
)

type Duration struct{ time.Duration }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return err
	}
	d.Duration = v
	return nil
}

// TLS names the certificate files. They are re-read every ReloadInterval,
// so certificates can be rotated (pfapid pki, Vault agent, spiffe-helper,
// cert-manager, ...) without a restart.
type TLS struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
	// ClientCAs: named bundles of CA certificates that may issue client
	// certificates, e.g. {"pfapid": "/etc/pfapid/ca.crt", "corp":
	// "/etc/ssl/corp-root.pem"}. Every client is bound to one bundle.
	ClientCAs map[string]string `json:"client_cas"`
	// ClientCA is the single-bundle shorthand (bundle name "default").
	ClientCA       string   `json:"client_ca"`
	ReloadInterval Duration `json:"reload_interval"`
}

// CABundles returns the client CA bundles by name.
func (t TLS) CABundles() map[string]string {
	if t.ClientCA != "" {
		return map[string]string{"default": t.ClientCA}
	}
	return t.ClientCAs
}

type Config struct {
	Listen         string       `json:"listen"`
	User           string       `json:"user"`
	TLS            TLS          `json:"tls"`
	ConfirmTimeout Duration     `json:"confirm_timeout"`
	AnchorDir      string       `json:"anchor_dir"`
	IncludeFile    string       `json:"include_file"`
	BaseRuleset    string       `json:"base_ruleset"`
	QueueFile      string       `json:"queue_file"`
	QoSFile        string       `json:"qos_file"`
	StateDir       string       `json:"state_dir"`
	Pfctl          string       `json:"pfctl"`
	RateLimit      float64      `json:"rate_limit"`
	RateBurst      int          `json:"rate_burst"`
	Policy         model.Policy `json:"policy"`
	Clients        []api.Client `json:"clients"`
}

func Load(path string) (*Config, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- operator-supplied config path
	if err != nil {
		return nil, err
	}
	c := &Config{
		User:           "_pfapid",
		ConfirmTimeout: Duration{60 * time.Second},
		AnchorDir:      "/etc/pf.anchors/api",
		IncludeFile:    "/etc/pf.anchors/api.conf",
		BaseRuleset:    "/etc/pf.conf",
		QueueFile:      "/etc/pf.anchors/api-queues.conf",
		QoSFile:        "/etc/pf.anchors/api-qos.conf",
		StateDir:       "/var/db/pfapid",
		Pfctl:          "/sbin/pfctl",
	}
	c.TLS.ReloadInterval = Duration{time.Minute}
	if err := json.Unmarshal(b, c); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, c.validate()
}

func (c *Config) validate() error {
	var errs []error
	if c.Listen == "" {
		errs = append(errs, errors.New("listen is required (an address on the management interface)"))
	}
	errs = append(errs, c.TLS.validate()...)
	if c.ConfirmTimeout.Duration < 10*time.Second || c.ConfirmTimeout.Duration > 10*time.Minute {
		errs = append(errs, errors.New("confirm_timeout must be between 10s and 10m"))
	}
	if err := c.Policy.Validate(); err != nil {
		errs = append(errs, err)
	}
	if len(c.Clients) == 0 {
		errs = append(errs, errors.New("at least one client is required"))
	}
	return errors.Join(errs...)
}

func (t TLS) validate() []error {
	var errs []error
	if t.Cert == "" || t.Key == "" {
		errs = append(errs, errors.New("tls.cert and tls.key are required"))
	}
	switch {
	case t.ClientCA != "" && len(t.ClientCAs) > 0:
		errs = append(errs, errors.New("set tls.client_ca or tls.client_cas, not both"))
	case t.ClientCA == "" && len(t.ClientCAs) == 0:
		errs = append(errs, errors.New("tls.client_cas (or tls.client_ca) is required"))
	}
	for name, path := range t.ClientCAs {
		if !model.ValidName(name) || path == "" {
			errs = append(errs, fmt.Errorf("tls.client_cas: bundle %q", name))
		}
	}
	if r := t.ReloadInterval.Duration; r != 0 && (r < 10*time.Second || r > time.Hour) {
		errs = append(errs, errors.New("tls.reload_interval must be 0 (off) or between 10s and 1h"))
	}
	return errs
}

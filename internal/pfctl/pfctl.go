// Package pfctl runs /sbin/pfctl with fixed argument vectors.
//
// No shell is involved, the environment is empty, and every variable part of
// an argv (anchor and table names, file paths) is checked here again even
// though the caller validated it: these calls run as root.
package pfctl

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/pderuiter/pfapid/internal/model"
)

// Runner is the set of pf operations pfapid needs. Exec implements it with
// the real pfctl; tests use a fake.
type Runner interface {
	// CheckAnchor parses file as anchor api/<name> without loading it and
	// returns pfctl's normalised (-nv) rendering of the rules.
	CheckAnchor(ctx context.Context, name, file string) ([]byte, error)
	LoadAnchor(ctx context.Context, name, file string) error
	FlushAnchor(ctx context.Context, name string) error
	// AnchorRules returns the loaded rules of api/<name> (-sr).
	AnchorRules(ctx context.Context, name string) ([]byte, error)
	ReplaceTable(ctx context.Context, name, file string) error
	TableEntries(ctx context.Context, name string) ([]byte, error)
	// CheckMain parses file as a main ruleset without loading it (-nvf) and
	// returns pfctl's normalised rendering.
	CheckMain(ctx context.Context, file string) ([]byte, error)
	// LoadMain reloads the base ruleset (Exec.MainFile). Used for QoS only:
	// queues exist only in the main ruleset (M0 T1b).
	LoadMain(ctx context.Context) error
	Queues(ctx context.Context) ([]byte, error)
	// QoSRules returns the loaded rules of the QoSAnchor anchor.
	QoSRules(ctx context.Context) ([]byte, error)
}

// QoSAnchor is the anchor the base ruleset loads the QoS rules into. It is
// outside api/* because it is loaded by the main reload, not at runtime.
const QoSAnchor = "api-qos"

// Exec runs the real pfctl binary.
type Exec struct {
	Path    string        // default /sbin/pfctl
	Timeout time.Duration // per call, default 30s
	// FileDirs: every file argument must live directly in one of these.
	FileDirs []string
	// MainFile is the base ruleset LoadMain loads (default /etc/pf.conf).
	MainFile string
}

// Error carries pfctl's (truncated) stderr.
type Error struct {
	Args   []string
	Stderr string
	Err    error
}

func (e *Error) Error() string {
	return fmt.Sprintf("pfctl %s: %v: %s", strings.Join(e.Args, " "), e.Err, e.Stderr)
}

func (e *Error) Unwrap() error { return e.Err }

var errArg = errors.New("pfctl: refused argument")

func (x Exec) file(f string) (string, error) {
	if strings.ContainsAny(f, "\n\x00") || !filepath.IsAbs(f) {
		return "", fmt.Errorf("%w: file %q", errArg, f)
	}
	for _, d := range x.FileDirs {
		if d != "" && filepath.Dir(f) == filepath.Clean(d) {
			return f, nil
		}
	}
	return "", fmt.Errorf("%w: file %q not in an allowed directory", errArg, f)
}

func anchorArg(name string) (string, error) {
	if !model.ValidName(name) {
		return "", fmt.Errorf("%w: anchor %q", errArg, name)
	}
	return "api/" + name, nil
}

func (x Exec) run(ctx context.Context, args ...string) ([]byte, error) {
	path := x.Path
	if path == "" {
		path = "/sbin/pfctl"
	}
	to := x.Timeout
	if to == 0 {
		to = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, to)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, args...) // #nosec G204 -- fixed binary, argv built from validated names only
	cmd.Env = []string{}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := stderr.String()
		if len(msg) > 2048 {
			msg = msg[:2048] + "..."
		}
		return nil, &Error{Args: args, Stderr: strings.TrimSpace(msg), Err: err}
	}
	return stdout.Bytes(), nil
}

func (x Exec) CheckAnchor(ctx context.Context, name, file string) ([]byte, error) {
	a, err := anchorArg(name)
	if err != nil {
		return nil, err
	}
	f, err := x.file(file)
	if err != nil {
		return nil, err
	}
	out, err := x.run(ctx, "-nv", "-a", a, "-f", f)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (x Exec) LoadAnchor(ctx context.Context, name, file string) error {
	a, err := anchorArg(name)
	if err != nil {
		return err
	}
	f, err := x.file(file)
	if err != nil {
		return err
	}
	_, err = x.run(ctx, "-a", a, "-f", f)
	return err
}

func (x Exec) FlushAnchor(ctx context.Context, name string) error {
	a, err := anchorArg(name)
	if err != nil {
		return err
	}
	_, err = x.run(ctx, "-a", a, "-F", "rules")
	return err
}

func (x Exec) AnchorRules(ctx context.Context, name string) ([]byte, error) {
	a, err := anchorArg(name)
	if err != nil {
		return nil, err
	}
	return x.run(ctx, "-a", a, "-s", "rules")
}

func (x Exec) ReplaceTable(ctx context.Context, name, file string) error {
	if !model.ValidName(name) {
		return fmt.Errorf("%w: table %q", errArg, name)
	}
	f, err := x.file(file)
	if err != nil {
		return err
	}
	_, err = x.run(ctx, "-t", name, "-T", "replace", "-f", f)
	return err
}

func (x Exec) TableEntries(ctx context.Context, name string) ([]byte, error) {
	if !model.ValidName(name) {
		return nil, fmt.Errorf("%w: table %q", errArg, name)
	}
	return x.run(ctx, "-t", name, "-T", "show")
}

// NormaliseRules turns pfctl rule output into comparable lines: macro
// definitions (printed by -nv, M0 T3) and blank lines are dropped and
// whitespace is collapsed.
func NormaliseRules(out []byte) []string {
	var lines []string
	for _, l := range strings.Split(string(out), "\n") {
		l = strings.Join(strings.Fields(l), " ")
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		if f := strings.Fields(l); len(f) >= 2 && f[1] == "=" {
			continue // macro definition
		}
		lines = append(lines, l)
	}
	return lines
}

func (x Exec) CheckMain(ctx context.Context, file string) ([]byte, error) {
	f, err := x.file(file)
	if err != nil {
		return nil, err
	}
	return x.run(ctx, "-nv", "-f", f)
}

func (x Exec) LoadMain(ctx context.Context) error {
	f := x.MainFile
	if f == "" {
		f = "/etc/pf.conf"
	}
	if !filepath.IsAbs(f) || strings.ContainsAny(f, "\n\x00") {
		return fmt.Errorf("%w: main file %q", errArg, f)
	}
	_, err := x.run(ctx, "-f", f)
	return err
}

func (x Exec) Queues(ctx context.Context) ([]byte, error) {
	return x.run(ctx, "-s", "queue")
}

func (x Exec) QoSRules(ctx context.Context) ([]byte, error) {
	return x.run(ctx, "-a", QoSAnchor, "-s", "rules")
}

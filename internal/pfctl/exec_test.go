package pfctl

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fakePfctl writes a script that prints its argv (one per line) and its
// HOME and a variable the test sets (neither may reach pfctl), and fails with a long stderr when an argument is "fail".
func fakePfctl(t *testing.T) (Exec, string) {
	t.Helper()
	t.Setenv("PFAPID_TEST_LEAK", "leaked")
	dir := t.TempDir()
	script := `#!/bin/sh
for a in "$@"; do
	if [ "$a" = "fail" ] || [ "$a" = "` + filepath.Join(dir, "fail") + `" ]; then
		i=0; while [ $i -lt 300 ]; do printf 'syntax error line %d\n' $i >&2; i=$((i+1)); done
		exit 1
	fi
	if [ "$a" = "` + filepath.Join(dir, "slow") + `" ]; then exec sleep 5; fi
done
echo "env=${HOME:-unset}:${PFAPID_TEST_LEAK:-unset}"
for a in "$@"; do echo "$a"; done
`
	p := filepath.Join(dir, "pfctl")
	if err := os.WriteFile(p, []byte(script), 0o700); err != nil { // #nosec G306 -- test helper must be executable
		t.Fatal(err)
	}
	return Exec{Path: p, FileDirs: []string{dir}, MainFile: filepath.Join(dir, "pf.conf")}, dir
}

func argv(t *testing.T, out []byte) string {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	if len(lines) == 0 || lines[0] != "env=unset:unset" {
		t.Fatalf("pfctl must run with an empty environment, got %q", lines[0])
	}
	return strings.Join(lines[1:], " ")
}

func TestExecArgv(t *testing.T) {
	x, dir := fakePfctl(t)
	ctx := context.Background()
	f := filepath.Join(dir, "a.conf")

	out, err := x.CheckAnchor(ctx, "k8s", f)
	if err != nil || argv(t, out) != "-nv -a api/k8s -f "+f {
		t.Fatalf("CheckAnchor: %q %v", out, err)
	}
	out, err = x.AnchorRules(ctx, "k8s")
	if err != nil || argv(t, out) != "-a api/k8s -s rules" {
		t.Fatalf("AnchorRules: %q %v", out, err)
	}
	out, err = x.TableEntries(ctx, "k8s_nodes")
	if err != nil || argv(t, out) != "-t k8s_nodes -T show" {
		t.Fatalf("TableEntries: %q %v", out, err)
	}
	out, err = x.CheckMain(ctx, f)
	if err != nil || argv(t, out) != "-nv -f "+f {
		t.Fatalf("CheckMain: %q %v", out, err)
	}
	out, err = x.Queues(ctx)
	if err != nil || argv(t, out) != "-s queue" {
		t.Fatalf("Queues: %q %v", out, err)
	}
	out, err = x.QoSRules(ctx)
	if err != nil || argv(t, out) != "-a api-qos -s rules" {
		t.Fatalf("QoSRules: %q %v", out, err)
	}
	for name, err := range map[string]error{
		"LoadAnchor":   x.LoadAnchor(ctx, "k8s", f),
		"FlushAnchor":  x.FlushAnchor(ctx, "k8s"),
		"ReplaceTable": x.ReplaceTable(ctx, "k8s_nodes", f),
		"LoadMain":     x.LoadMain(ctx),
	} {
		if err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestExecErrors(t *testing.T) {
	x, dir := fakePfctl(t)
	ctx := context.Background()

	_, err := x.CheckAnchor(ctx, "k8s", filepath.Join(dir, "fail"))
	var pe *Error
	if !errors.As(err, &pe) {
		t.Fatalf("want *Error, got %v", err)
	}
	if len(pe.Stderr) > 2048+3 || !strings.HasSuffix(pe.Stderr, "...") || !strings.Contains(pe.Error(), "syntax error line 0") {
		t.Fatalf("stderr not truncated or missing: %d bytes", len(pe.Stderr))
	}
	if pe.Unwrap() == nil || !strings.Contains(pe.Error(), "-nv -a api/k8s") {
		t.Fatalf("error: %v", pe)
	}

	// Refused arguments never reach pfctl.
	for name, err := range map[string]error{
		"AnchorRules":  func() error { _, e := x.AnchorRules(ctx, "Bad"); return e }(),
		"TableEntries": func() error { _, e := x.TableEntries(ctx, "bad table"); return e }(),
		"CheckMain":    func() error { _, e := x.CheckMain(ctx, "/etc/pf.conf"); return e }(),
		"CheckAnchor":  func() error { _, e := x.CheckAnchor(ctx, "ok", "/tmp/x\nload"); return e }(),
		"CheckAnchorName": func() error {
			_, e := x.CheckAnchor(ctx, "../x", filepath.Join(dir, "a"))
			return e
		}(),
		"ReplaceTableFile": x.ReplaceTable(ctx, "t", "/etc/passwd"),
		"LoadMainRelative": Exec{Path: x.Path, MainFile: "pf.conf"}.LoadMain(ctx),
	} {
		if !errors.Is(err, errArg) {
			t.Errorf("%s: want refused argument, got %v", name, err)
		}
	}

	// Timeout: the call is killed.
	x.Timeout = 200 * time.Millisecond
	start := time.Now()
	if _, err := x.CheckMain(ctx, filepath.Join(dir, "slow")); err == nil || time.Since(start) > 4*time.Second {
		t.Fatalf("timeout not enforced: %v after %v", err, time.Since(start))
	}
}

func TestExecDefaults(t *testing.T) {
	// The default binary path is /sbin/pfctl; where it does not exist the
	// call fails with an *Error rather than running anything else.
	if _, err := os.Stat("/sbin/pfctl"); err == nil {
		t.Skip("real pfctl present")
	}
	var pe *Error
	if _, err := (Exec{}).Queues(context.Background()); !errors.As(err, &pe) {
		t.Fatalf("default path: %v", err)
	}
	if err := (Exec{}).LoadMain(context.Background()); !errors.As(err, &pe) || !strings.Contains(pe.Error(), "/etc/pf.conf") {
		t.Fatalf("default main file: %v", err)
	}
}

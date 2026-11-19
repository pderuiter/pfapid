package priv

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/pderuiter/pfapid/internal/model"
	"github.com/pderuiter/pfapid/internal/store"
)

// fakePF mimics pfctl: loaded anchors and tables live in maps.
type fakePF struct {
	anchors map[string]string
	tables  map[string]string
	reject  string // CheckAnchor fails when the file contains this
	calls   []string
	// Main ruleset: what LoadMain loaded from the QoS files.
	queueFile, qosFile string
	queues, qos        string
	mainLoads          int
}

var includeRe = regexp.MustCompile(`^include "([^"]+)"$`)
var loadQoSRe = regexp.MustCompile(`^load anchor "api-qos" from "([^"]+)"$`)

// CheckMain expands include and the api-qos load like pfctl -nv would.
func (f *fakePF) CheckMain(_ context.Context, file string) ([]byte, error) {
	f.calls = append(f.calls, "checkmain")
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var out strings.Builder
	for _, l := range strings.Split(string(b), "\n") {
		if m := includeRe.FindStringSubmatch(l); m != nil {
			inc, err := os.ReadFile(m[1]) // #nosec G304 G703 -- test fake, paths from the test's own files
			if err != nil {
				return nil, err
			}
			out.Write(inc)
		} else if m := loadQoSRe.FindStringSubmatch(l); m != nil {
			r, err := os.ReadFile(m[1]) // #nosec G304 G703 -- test fake, paths from the test's own files
			if err != nil {
				return nil, err
			}
			out.Write(r)
		} else if l != "" {
			out.WriteString(l + "\n")
		}
	}
	if f.reject != "" && strings.Contains(out.String(), f.reject) {
		return nil, errors.New("syntax error")
	}
	return []byte(out.String()), nil
}
func (f *fakePF) LoadMain(context.Context) error {
	f.calls = append(f.calls, "loadmain")
	q, err := os.ReadFile(f.queueFile)
	if err != nil {
		return err
	}
	r, err := os.ReadFile(f.qosFile)
	if err != nil {
		return err
	}
	if f.reject != "" && strings.Contains(string(q)+string(r), f.reject) {
		return errors.New("syntax error")
	}
	f.mainLoads++
	f.queues, f.qos = string(q), string(r)
	return nil
}
func (f *fakePF) Queues(context.Context) ([]byte, error)   { return []byte(f.queues), nil }
func (f *fakePF) QoSRules(context.Context) ([]byte, error) { return []byte(f.qos), nil }

func newFake() *fakePF { return &fakePF{anchors: map[string]string{}, tables: map[string]string{}} }

func (f *fakePF) CheckAnchor(_ context.Context, name, file string) ([]byte, error) {
	f.calls = append(f.calls, "check "+name)
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	if f.reject != "" && strings.Contains(string(b), f.reject) {
		return nil, errors.New("syntax error")
	}
	return b, nil
}
func (f *fakePF) LoadAnchor(_ context.Context, name, file string) error {
	f.calls = append(f.calls, "load "+name)
	b, err := os.ReadFile(file)
	f.anchors[name] = string(b)
	return err
}
func (f *fakePF) FlushAnchor(_ context.Context, name string) error {
	f.calls = append(f.calls, "flush "+name)
	delete(f.anchors, name)
	return nil
}
func (f *fakePF) AnchorRules(_ context.Context, name string) ([]byte, error) {
	return []byte(f.anchors[name]), nil
}
func (f *fakePF) ReplaceTable(_ context.Context, name, file string) error {
	b, err := os.ReadFile(file)
	f.tables[name] = string(b)
	return err
}
func (f *fakePF) TableEntries(_ context.Context, name string) ([]byte, error) {
	return []byte(f.tables[name]), nil
}

type harness struct {
	s      *Server
	pf     *fakePF
	dir    string
	expire func() // fires the pending change's timer
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(filepath.Join(dir, "state"))
	if err != nil {
		t.Fatal(err)
	}
	pf := newFake()
	pf.queueFile, pf.qosFile = filepath.Join(dir, "api-queues.conf"), filepath.Join(dir, "api-qos.conf")
	base := filepath.Join(dir, "pf.conf")
	if err := os.WriteFile(base, []byte("pass\ninclude \""+pf.queueFile+"\"\nanchor \"api-qos\"\nload anchor \"api-qos\" from \""+pf.qosFile+"\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := New(Config{
		BaseRuleset: base,
		QueueFile:   pf.queueFile,
		QoSFile:     pf.qosFile,
		Policy: model.Policy{Interfaces: []string{"frontend", "backend"}, Tables: []string{"k8s_nodes"},
			QueueInterfaces: []string{"vio1", "vio2"}},
		ConfirmTimeout: time.Minute,
		AnchorDir:      filepath.Join(dir, "anchors"),
		IncludeFile:    filepath.Join(dir, "api.conf"),
		WorkDir:        filepath.Join(dir, "work"),
	}, pf, st, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{s: s, pf: pf, dir: dir}
	s.after = func(_ time.Duration, fn func()) *time.Timer {
		h.expire = fn
		return time.NewTimer(time.Hour)
	}
	return h
}

func anchor(port uint16) model.Anchor {
	return model.Anchor{Name: "k8s-prod", Rules: []model.Rule{{
		Action: model.Pass, Direction: model.In, Interface: "frontend", Family: model.Inet, Protocol: model.TCP,
		To: model.Endpoint{Table: "k8s_nodes", Ports: []model.PortRange{{From: port}}},
	}}}
}

var ctx = context.Background()

func code(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

func TestCreateConfirm(t *testing.T) {
	h := newHarness(t)
	if _, err := h.s.PutAnchor(ctx, "tf", anchor(443), Precondition{}); code(err) != CodePrecondition {
		t.Fatalf("create without If-None-Match: %v", err)
	}
	ci, err := h.s.PutAnchor(ctx, "tf", anchor(443), Precondition{IfNoneMatch: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.pf.anchors["k8s-prod"], "port 443") {
		t.Fatal("not loaded")
	}
	inc, _ := os.ReadFile(filepath.Join(h.dir, "api.conf"))
	if !strings.Contains(string(inc), `load anchor "api/k8s-prod"`) {
		t.Fatalf("include file: %s", inc)
	}
	// Not committed yet.
	if _, err := h.s.GetAnchor(ctx, "k8s-prod"); code(err) != CodeNotFound {
		t.Fatalf("visible before confirm: %v", err)
	}
	// A second change is refused while one is pending.
	if _, err := h.s.PutAnchor(ctx, "tf", anchor(80), Precondition{IfNoneMatch: true}); code(err) != CodeConflict {
		t.Fatalf("want conflict, got %v", err)
	}
	// Someone else cannot confirm.
	if err := h.s.Confirm(ctx, "other", ci.ID, false); code(err) != CodeForbidden {
		t.Fatalf("want forbidden, got %v", err)
	}
	if err := h.s.Confirm(ctx, "tf", ci.ID, false); err != nil {
		t.Fatal(err)
	}
	st, err := h.s.GetAnchor(ctx, "k8s-prod")
	if err != nil || st.ETag != ci.ETag {
		t.Fatalf("after confirm: %+v %v", st, err)
	}
	d, err := h.s.DriftAnchor(ctx, "k8s-prod")
	if err != nil || !d.InSync {
		t.Fatalf("drift: %+v %v", d, err)
	}
}

func TestUpdateExpiresAndRollsBack(t *testing.T) {
	h := newHarness(t)
	ci, _ := h.s.PutAnchor(ctx, "tf", anchor(443), Precondition{IfNoneMatch: true})
	_ = h.s.Confirm(ctx, "tf", ci.ID, false)
	st, _ := h.s.GetAnchor(ctx, "k8s-prod")

	if _, err := h.s.PutAnchor(ctx, "tf", anchor(8443), Precondition{IfMatch: "stale"}); code(err) != CodePrecondition {
		t.Fatalf("stale etag: %v", err)
	}
	if _, err := h.s.PutAnchor(ctx, "tf", anchor(8443), Precondition{IfMatch: st.ETag}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.pf.anchors["k8s-prod"], "port 8443") {
		t.Fatal("update not loaded")
	}
	h.expire() // nobody confirmed
	if !strings.Contains(h.pf.anchors["k8s-prod"], "port 443") || strings.Contains(h.pf.anchors["k8s-prod"], "8443") {
		t.Fatalf("not rolled back: %s", h.pf.anchors["k8s-prod"])
	}
	if p, _ := h.s.Pending(ctx); p != nil {
		t.Fatal("still pending after expiry")
	}
	file, _ := os.ReadFile(filepath.Join(h.dir, "anchors", "k8s-prod.conf"))
	if !strings.Contains(string(file), "port 443") {
		t.Fatal("anchor file not restored")
	}
}

func TestCreateExpiresRemovesAnchor(t *testing.T) {
	h := newHarness(t)
	_, _ = h.s.PutAnchor(ctx, "tf", anchor(443), Precondition{IfNoneMatch: true})
	h.expire()
	if _, ok := h.pf.anchors["k8s-prod"]; ok {
		t.Fatal("anchor still loaded")
	}
	if _, err := os.Stat(filepath.Join(h.dir, "anchors", "k8s-prod.conf")); !os.IsNotExist(err) {
		t.Fatal("anchor file left behind")
	}
}

func TestPfctlRejectLeavesStateUnchanged(t *testing.T) {
	h := newHarness(t)
	h.pf.reject = "port 443"
	if _, err := h.s.PutAnchor(ctx, "tf", anchor(443), Precondition{IfNoneMatch: true}); code(err) != CodePFRejected {
		t.Fatalf("want pf_rejected, got %v", err)
	}
	if p, _ := h.s.Pending(ctx); p != nil {
		t.Fatal("rejected change is pending")
	}
	if len(h.pf.anchors) != 0 {
		t.Fatal("rejected anchor loaded")
	}
}

func TestDeleteAndRollback(t *testing.T) {
	h := newHarness(t)
	ci, _ := h.s.PutAnchor(ctx, "tf", anchor(443), Precondition{IfNoneMatch: true})
	_ = h.s.Confirm(ctx, "tf", ci.ID, false)
	st, _ := h.s.GetAnchor(ctx, "k8s-prod")
	del, err := h.s.DeleteAnchor(ctx, "tf", "k8s-prod", Precondition{IfMatch: st.ETag})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := h.pf.anchors["k8s-prod"]; ok {
		t.Fatal("not flushed")
	}
	if err := h.s.Rollback(ctx, "tf", del.ID, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.pf.anchors["k8s-prod"], "port 443") {
		t.Fatal("delete not rolled back")
	}
}

func TestTable(t *testing.T) {
	h := newHarness(t)
	st, err := h.s.GetTable(ctx, "k8s_nodes")
	if err != nil {
		t.Fatal(err)
	}
	tb := model.Table{Name: "k8s_nodes", Entries: []netip.Prefix{netip.MustParsePrefix("10.70.1.10/32"), netip.MustParsePrefix("2001:db8::10/128")}}
	ci, err := h.s.PutTable(ctx, "tf", tb, Precondition{IfMatch: st.ETag})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.pf.tables["k8s_nodes"], "2001:db8::10/128") {
		t.Fatalf("table not replaced: %q", h.pf.tables["k8s_nodes"])
	}
	h.pf.tables["k8s_nodes"] = "   10.70.1.10\n   2001:db8::10\n" // pfctl -T show format
	if d, _ := h.s.DriftTable(ctx, "k8s_nodes"); !d.InSync {
		t.Fatalf("drift: %+v", d)
	}
	h.expire()
	if h.pf.tables["k8s_nodes"] != "" {
		t.Fatalf("table not restored to empty: %q", h.pf.tables["k8s_nodes"])
	}
	_ = ci
	if _, err := h.s.GetTable(ctx, "unmanaged"); code(err) != CodeNotFound {
		t.Fatal("unmanaged table readable")
	}
}

func TestReconcileUndoesUnconfirmed(t *testing.T) {
	h := newHarness(t)
	ci, _ := h.s.PutAnchor(ctx, "tf", anchor(443), Precondition{IfNoneMatch: true})
	_ = h.s.Confirm(ctx, "tf", ci.ID, false)
	st, _ := h.s.GetAnchor(ctx, "k8s-prod")
	_, _ = h.s.PutAnchor(ctx, "tf", anchor(8443), Precondition{IfMatch: st.ETag})
	other := model.Anchor{Name: "stray", Rules: anchor(22).Rules}
	_ = os.WriteFile(filepath.Join(h.dir, "anchors", "stray.conf"), []byte("x"), 0o600)
	_ = other

	// Simulate a restart: a new server over the same directories.
	h2 := newHarness(t)
	h2.s.cfg = h.s.cfg
	h2.s.st = h.s.st
	h2.pf.anchors = h.pf.anchors
	h2.pf.queueFile, h2.pf.qosFile = h.pf.queueFile, h.pf.qosFile
	if err := h2.s.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h2.pf.anchors["k8s-prod"], "port 443") || strings.Contains(h2.pf.anchors["k8s-prod"], "8443") {
		t.Fatalf("unconfirmed change survived restart: %s", h2.pf.anchors["k8s-prod"])
	}
	if _, err := os.Stat(filepath.Join(h.dir, "anchors", "stray.conf")); !os.IsNotExist(err) {
		t.Fatal("stray anchor file kept")
	}
}

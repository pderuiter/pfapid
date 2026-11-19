package store

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pderuiter/pfapid/internal/model"
)

func open(t *testing.T) (*Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"anchors", "tables", "qos", "history"} {
		fi, err := os.Stat(filepath.Join(dir, sub))
		if err != nil || fi.Mode().Perm() != 0o700 {
			t.Fatalf("%s: %v %v", sub, fi, err)
		}
	}
	return s, dir
}

func TestAnchorsAndTables(t *testing.T) {
	s, dir := open(t)
	if _, err := s.GetAnchor("k8s"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing anchor: %v", err)
	}
	a := model.Anchor{Name: "k8s", Rules: []model.Rule{{Action: model.Pass}}}
	if err := s.PutAnchor(a); err != nil {
		t.Fatal(err)
	}
	if err := s.PutAnchor(model.Anchor{Name: "alpha"}); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetAnchor("k8s")
	if err != nil || ETag(got) != ETag(a) {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	fi, _ := os.Stat(filepath.Join(dir, "anchors", "k8s.json"))
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("anchor file mode %v", fi.Mode())
	}
	// Junk in the directory is ignored by list.
	_ = os.WriteFile(filepath.Join(dir, "anchors", "notes.txt"), nil, 0o600)
	_ = os.WriteFile(filepath.Join(dir, "anchors", "Bad Name.json"), nil, 0o600)
	_ = os.Mkdir(filepath.Join(dir, "anchors", "sub.json"), 0o700)
	names, err := s.ListAnchors()
	if err != nil || strings.Join(names, ",") != "alpha,k8s" {
		t.Fatalf("list: %v %v", names, err)
	}
	if err := s.DeleteAnchor("k8s"); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteAnchor("k8s"); err != nil {
		t.Fatalf("deleting a missing anchor must be a no-op: %v", err)
	}
	if _, err := s.GetAnchor("k8s"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted anchor: %v", err)
	}

	tb := model.Table{Name: "k8s_nodes", Entries: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}
	if err := s.PutTable(tb); err != nil {
		t.Fatal(err)
	}
	gt, err := s.GetTable("k8s_nodes")
	if err != nil || len(gt.Entries) != 1 || gt.Entries[0] != tb.Entries[0] {
		t.Fatalf("table: %+v %v", gt, err)
	}
	if names, err := s.ListTables(); err != nil || len(names) != 1 {
		t.Fatalf("tables: %v %v", names, err)
	}
}

func TestQoS(t *testing.T) {
	s, _ := open(t)
	if _, err := s.GetQoS(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unset QoS: %v", err)
	}
	q := model.QoS{Queues: []model.Queue{{Name: "root", Interface: "vio1", Bandwidth: "100M"}}}
	if err := s.PutQoS(q); err != nil {
		t.Fatal(err)
	}
	got, err := s.GetQoS()
	if err != nil || ETag(got) != ETag(q) {
		t.Fatalf("qos: %+v %v", got, err)
	}
}

// Names are validated again: a path traversal never reaches the filesystem.
func TestInvalidNames(t *testing.T) {
	s, _ := open(t)
	for _, n := range []string{"../etc/passwd", "", "A", "a/b"} {
		if _, err := s.GetAnchor(n); err == nil || errors.Is(err, ErrNotFound) {
			t.Errorf("get %q: %v", n, err)
		}
		if err := s.PutAnchor(model.Anchor{Name: n}); err == nil {
			t.Errorf("put %q accepted", n)
		}
		if err := s.DeleteAnchor(n); err == nil {
			t.Errorf("delete %q accepted", n)
		}
	}
}

func TestCorruptAndUnreadable(t *testing.T) {
	s, dir := open(t)
	_ = os.WriteFile(filepath.Join(dir, "tables", "t.json"), []byte("{not json"), 0o600)
	if _, err := s.GetTable("t"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("corrupt file: %v", err)
	}
	// A directory where a file should be: read error, not ErrNotFound.
	_ = os.Mkdir(filepath.Join(dir, "anchors", "d.json"), 0o700)
	if _, err := s.GetAnchor("d"); err == nil || errors.Is(err, ErrNotFound) {
		t.Fatalf("directory as file: %v", err)
	}
	_ = os.RemoveAll(filepath.Join(dir, "tables"))
	if _, err := s.ListTables(); err == nil {
		t.Fatal("list of a missing directory succeeded")
	}
	// Open fails when the state dir is a file.
	f := filepath.Join(t.TempDir(), "file")
	_ = os.WriteFile(f, nil, 0o600)
	if _, err := Open(f); err == nil {
		t.Fatal("Open on a file succeeded")
	}
}

func TestHistory(t *testing.T) {
	s, dir := open(t)
	h := HistoryEntry{ChangeID: "0123456789abcdef", Actor: "tf", Kind: "anchor", Name: "k8s", Outcome: "confirmed",
		Time: time.Date(2026, 1, 2, 3, 4, 5, 6, time.FixedZone("x", 3600)), After: json.RawMessage(`{"name":"k8s"}`)}
	if err := s.AppendHistory(h); err != nil {
		t.Fatal(err)
	}
	ents, _ := os.ReadDir(filepath.Join(dir, "history"))
	if len(ents) != 1 || ents[0].Name() != "20260102T020405.000000006Z-0123456789abcdef.json" {
		t.Fatalf("history files: %v", ents)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "history", ents[0].Name()))
	var back HistoryEntry
	if err := json.Unmarshal(b, &back); err != nil || back.Outcome != "confirmed" || strings.Join(strings.Fields(string(back.After)), "") != `{"name":"k8s"}` {
		t.Fatalf("history entry: %+v %v", back, err)
	}
}

func TestWriteFileAtomic(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := WriteFileAtomic(p, []byte("one"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(p, []byte("two"), 0o644); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	fi, _ := os.Stat(p)
	if string(b) != "two" || fi.Mode().Perm() != 0o644 {
		t.Fatalf("content %q mode %v", b, fi.Mode())
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Fatalf("temp files left behind: %v", ents)
	}
	if err := WriteFileAtomic(filepath.Join(dir, "missing", "f"), nil, 0o600); err == nil {
		t.Fatal("write into a missing directory succeeded")
	}
	// Renaming over a directory fails, and the temp file is removed.
	_ = os.Mkdir(filepath.Join(dir, "d"), 0o700)
	_ = os.WriteFile(filepath.Join(dir, "d", "x"), nil, 0o600)
	if err := WriteFileAtomic(filepath.Join(dir, "d"), []byte("x"), 0o600); err == nil {
		t.Fatal("rename over a non-empty directory succeeded")
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 2 {
		t.Fatalf("temp file left behind: %v", ents)
	}
}

func TestETag(t *testing.T) {
	a := ETag(model.Anchor{Name: "a"})
	if len(a) != 32 || a == ETag(model.Anchor{Name: "b"}) || a != ETag(model.Anchor{Name: "a"}) {
		t.Fatalf("etag %q", a)
	}
	defer func() {
		if recover() == nil {
			t.Fatal("ETag of an unmarshalable value must panic")
		}
	}()
	ETag(func() {})
}

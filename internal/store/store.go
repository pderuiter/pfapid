// Package store keeps the COMMITTED (confirmed) desired state on disk.
//
// A change is written here only when it is confirmed. A change that is
// applied but never confirmed (timer expiry, pfapid crash or restart) is
// therefore undone by reconciling the kernel and the anchor files to this
// store at startup.
package store

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/pderuiter/pfapid/internal/model"
)

var ErrNotFound = errors.New("not found")

type Store struct{ dir string }

// Open prepares dir (anchors/, tables/, history/ with mode 0700).
func Open(dir string) (*Store, error) {
	for _, sub := range []string{"anchors", "tables", "qos", "history"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
			return nil, err
		}
	}
	return &Store{dir: dir}, nil
}

// ETag is the hex SHA-256 of the canonical JSON of v.
func ETag(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err) // model types always marshal
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:16])
}

// WriteFileAtomic writes data to path via a temp file, fsync and rename.
func WriteFileAtomic(path string, data []byte, mode os.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func (s *Store) path(kind, name string) (string, error) {
	if !model.ValidName(name) {
		return "", fmt.Errorf("store: invalid name %q", name)
	}
	return filepath.Join(s.dir, kind, name+".json"), nil
}

func (s *Store) get(kind, name string, v any) error {
	p, err := s.path(kind, name)
	if err != nil {
		return err
	}
	b, err := os.ReadFile(p) // #nosec G304 -- name validated, dir root-owned
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

func (s *Store) put(kind, name string, v any) error {
	p, err := s.path(kind, name)
	if err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return WriteFileAtomic(p, b, 0o600)
}

func (s *Store) del(kind, name string) error {
	p, err := s.path(kind, name)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *Store) list(kind string) ([]string, error) {
	ents, err := os.ReadDir(filepath.Join(s.dir, kind))
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range ents {
		n, ok := strings.CutSuffix(e.Name(), ".json")
		if ok && !e.IsDir() && model.ValidName(n) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return names, nil
}

func (s *Store) GetAnchor(name string) (model.Anchor, error) {
	var a model.Anchor
	err := s.get("anchors", name, &a)
	return a, err
}
func (s *Store) PutAnchor(a model.Anchor) error { return s.put("anchors", a.Name, a) }
func (s *Store) DeleteAnchor(name string) error { return s.del("anchors", name) }
func (s *Store) ListAnchors() ([]string, error) { return s.list("anchors") }
func (s *Store) PutTable(t model.Table) error   { return s.put("tables", t.Name, t) }
func (s *Store) ListTables() ([]string, error)  { return s.list("tables") }
func (s *Store) GetTable(name string) (model.Table, error) {
	var t model.Table
	err := s.get("tables", name, &t)
	return t, err
}

// GetQoS returns the committed QoS document (ErrNotFound if never set).
func (s *Store) GetQoS() (model.QoS, error) {
	var q model.QoS
	err := s.get("qos", "qos", &q)
	return q, err
}
func (s *Store) PutQoS(q model.QoS) error { return s.put("qos", "qos", q) }

// HistoryEntry records one finished change for audit and manual rollback.
type HistoryEntry struct {
	ChangeID string          `json:"change_id"`
	Actor    string          `json:"actor"`
	Kind     string          `json:"kind"`
	Name     string          `json:"name"`
	Outcome  string          `json:"outcome"` // confirmed | rolled_back | expired
	Time     time.Time       `json:"time"`
	Before   json.RawMessage `json:"before,omitempty"`
	After    json.RawMessage `json:"after,omitempty"`
}

func (s *Store) AppendHistory(h HistoryEntry) error {
	b, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return err
	}
	name := fmt.Sprintf("%s-%s.json", h.Time.UTC().Format("20060102T150405.000000000Z"), h.ChangeID)
	return WriteFileAtomic(filepath.Join(s.dir, "history", name), b, 0o600)
}

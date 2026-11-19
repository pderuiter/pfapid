// Package priv is the privileged (root) half of pfapid. It owns the anchor
// files, the include file, the state store and every pfctl call.
//
// Its security boundary: whatever the unprivileged network process asks for,
// the only effects possible are valid model objects loaded into api/*
// anchors and the contents of policy-listed tables. Every request is
// validated again here.
//
// Every mutation is commit-confirm: it is applied immediately, and undone
// automatically unless confirmed before the deadline. Only one change can be
// pending at a time. The store is written only on confirm, so a crash or
// restart with a pending change rolls it back on the next Reconcile.
package priv

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/pderuiter/pfapid/internal/model"
	"github.com/pderuiter/pfapid/internal/pfctl"
	"github.com/pderuiter/pfapid/internal/render"
	"github.com/pderuiter/pfapid/internal/store"
)

type Config struct {
	Policy         model.Policy
	ConfirmTimeout time.Duration
	AnchorDir      string // /etc/pf.anchors/api
	IncludeFile    string // /etc/pf.anchors/api.conf
	WorkDir        string // scratch files for checks and table input
	// QoS (empty: QoS disabled). See qos.go.
	BaseRuleset string // /etc/pf.conf, read to validate a QoS change
	QueueFile   string // /etc/pf.anchors/api-queues.conf
	QoSFile     string // /etc/pf.anchors/api-qos.conf
}

type change struct {
	info      ChangeInfo
	prevAnch  *model.Anchor // nil: did not exist
	nextAnch  *model.Anchor // nil: delete
	prevTable *model.Table
	nextTable *model.Table
	prevQoS   *model.QoS
	nextQoS   *model.QoS
	timer     *time.Timer
}

type Server struct {
	cfg   Config
	pf    pfctl.Runner
	st    *store.Store
	log   *slog.Logger
	mu    sync.Mutex
	pend  *change
	now   func() time.Time
	after func(time.Duration, func()) *time.Timer
}

func New(cfg Config, pf pfctl.Runner, st *store.Store, log *slog.Logger) (*Server, error) {
	if err := cfg.Policy.Validate(); err != nil {
		return nil, err
	}
	if cfg.ConfirmTimeout <= 0 {
		cfg.ConfirmTimeout = 60 * time.Second
	}
	for _, d := range []string{cfg.AnchorDir, cfg.WorkDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return nil, err
		}
	}
	return &Server{cfg: cfg, pf: pf, st: st, log: log, now: time.Now, after: time.AfterFunc}, nil
}

func newID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func (s *Server) anchorFile(name string) string { return filepath.Join(s.cfg.AnchorDir, name+".conf") }

// --- low-level apply helpers (caller holds s.mu) -------------------------

// loadAnchor renders a, checks it with pfctl -n, loads it and only then
// moves it into place. A failed check or load leaves the kernel and the
// file untouched (pfctl loads are atomic, M0 T4).
func (s *Server) loadAnchor(ctx context.Context, a model.Anchor) error {
	if err := a.Validate(s.cfg.Policy); err != nil {
		return err
	}
	text, err := render.Anchor(a)
	if err != nil {
		return errf(CodeInternal, "%v", err)
	}
	tmp := filepath.Join(s.cfg.AnchorDir, a.Name+".new")
	if err := store.WriteFileAtomic(tmp, text, 0o600); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if _, err := s.pf.CheckAnchor(ctx, a.Name, tmp); err != nil {
		return errf(CodePFRejected, "%v", err)
	}
	if err := s.pf.LoadAnchor(ctx, a.Name, tmp); err != nil {
		return errf(CodePFRejected, "%v", err)
	}
	return os.Rename(tmp, s.anchorFile(a.Name))
}

func (s *Server) removeAnchor(ctx context.Context, name string) error {
	if err := s.pf.FlushAnchor(ctx, name); err != nil {
		return errf(CodePFRejected, "%v", err)
	}
	if err := os.Remove(s.anchorFile(name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func (s *Server) replaceTable(ctx context.Context, t model.Table) error {
	if err := t.Validate(s.cfg.Policy); err != nil {
		return err
	}
	f := filepath.Join(s.cfg.WorkDir, t.Name+".entries")
	if err := store.WriteFileAtomic(f, render.TableEntries(t), 0o600); err != nil {
		return err
	}
	defer os.Remove(f)
	if err := s.pf.ReplaceTable(ctx, t.Name, f); err != nil {
		return errf(CodePFRejected, "%v", err)
	}
	return nil
}

// writeInclude regenerates the include file from the anchor files present.
func (s *Server) writeInclude() error {
	ents, err := os.ReadDir(s.cfg.AnchorDir)
	if err != nil {
		return err
	}
	var names []string
	for _, e := range ents {
		if n, ok := strings.CutSuffix(e.Name(), ".conf"); ok && model.ValidName(n) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	return store.WriteFileAtomic(s.cfg.IncludeFile, render.IncludeFile(s.cfg.AnchorDir, names), 0o644)
}

// --- reads ----------------------------------------------------------------

func (s *Server) pendingFor(kind, name string) string {
	if s.pend != nil && s.pend.info.Kind == kind && s.pend.info.Name == name {
		return s.pend.info.ID
	}
	return ""
}

func (s *Server) ListAnchors(context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.st.ListAnchors()
}

func (s *Server) GetAnchor(_ context.Context, name string) (AnchorState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !model.ValidName(name) {
		return AnchorState{}, errf(CodeInvalid, msgAnchorName, name)
	}
	a, err := s.st.GetAnchor(name)
	if errors.Is(err, store.ErrNotFound) {
		return AnchorState{PendingChange: s.pendingFor("anchor", name)}, errf(CodeNotFound, msgAnchorNotFound, name)
	}
	if err != nil {
		return AnchorState{}, err
	}
	return AnchorState{Anchor: a, ETag: store.ETag(a), PendingChange: s.pendingFor("anchor", name)}, nil
}

func (s *Server) ListTables(context.Context) ([]string, error) {
	return slices.Clone(s.cfg.Policy.Tables), nil
}

func (s *Server) GetTable(_ context.Context, name string) (TableState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !slices.Contains(s.cfg.Policy.Tables, name) {
		return TableState{}, errf(CodeNotFound, "table %q is not managed", name)
	}
	t, err := s.st.GetTable(name)
	if errors.Is(err, store.ErrNotFound) {
		t = model.Table{Name: name, Entries: nil}
	} else if err != nil {
		return TableState{}, err
	}
	return TableState{Table: t, ETag: store.ETag(t), PendingChange: s.pendingFor("table", name)}, nil
}

func (s *Server) Pending(context.Context) (*ChangeInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pend == nil {
		return nil, nil
	}
	ci := s.pend.info
	return &ci, nil
}

// ValidateAnchor is a dry run: model validation, rendering and pfctl -nv.
func (s *Server) ValidateAnchor(ctx context.Context, a model.Anchor) (ValidateResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := a.Validate(s.cfg.Policy); err != nil {
		return ValidateResult{}, AsError(err)
	}
	norm, rendered, err := s.normalised(ctx, a)
	if err != nil {
		return ValidateResult{}, err
	}
	return ValidateResult{Rendered: rendered, Normalised: norm}, nil
}

func (s *Server) normalised(ctx context.Context, a model.Anchor) (norm, rendered []string, err error) {
	text, err := render.Anchor(a)
	if err != nil {
		return nil, nil, errf(CodeInternal, "%v", err)
	}
	f := filepath.Join(s.cfg.WorkDir, a.Name+".check")
	if err := store.WriteFileAtomic(f, text, 0o600); err != nil {
		return nil, nil, err
	}
	defer os.Remove(f)
	out, err := s.pf.CheckAnchor(ctx, a.Name, f)
	if err != nil {
		return nil, nil, errf(CodePFRejected, "%v", err)
	}
	return pfctl.NormaliseRules(out), pfctl.NormaliseRules(text), nil
}

// DriftAnchor compares pfctl's normalised form of the desired anchor (the
// pending version if one is pending, else the committed one) with the rules
// loaded in the kernel (M0 T3: these are identical when in sync).
func (s *Server) DriftAnchor(ctx context.Context, name string) (DriftResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !model.ValidName(name) {
		return DriftResult{}, errf(CodeInvalid, msgAnchorName, name)
	}
	var want model.Anchor
	if s.pend != nil && s.pend.info.Kind == "anchor" && s.pend.info.Name == name {
		if s.pend.nextAnch == nil {
			want = model.Anchor{Name: name}
		} else {
			want = *s.pend.nextAnch
		}
	} else {
		a, err := s.st.GetAnchor(name)
		if errors.Is(err, store.ErrNotFound) {
			return DriftResult{}, errf(CodeNotFound, msgAnchorNotFound, name)
		}
		if err != nil {
			return DriftResult{}, err
		}
		want = a
	}
	expected, _, err := s.normalised(ctx, want)
	if err != nil {
		return DriftResult{}, err
	}
	out, err := s.pf.AnchorRules(ctx, name)
	if err != nil {
		return DriftResult{}, errf(CodePFRejected, "%v", err)
	}
	live := pfctl.NormaliseRules(out)
	return DriftResult{InSync: slices.Equal(expected, live), Expected: expected, Live: live}, nil
}

func (s *Server) DriftTable(ctx context.Context, name string) (DriftResult, error) {
	st, err := s.GetTable(ctx, name)
	if err != nil {
		return DriftResult{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	want := st.Table
	if s.pend != nil && s.pend.info.Kind == "table" && s.pend.info.Name == name {
		want = *s.pend.nextTable
	}
	expected := make([]string, 0, len(want.Entries))
	for _, p := range want.Entries {
		expected = append(expected, canonicalEntry(p.String()))
	}
	out, err := s.pf.TableEntries(ctx, name)
	if err != nil {
		return DriftResult{}, errf(CodePFRejected, "%v", err)
	}
	var live []string
	for _, l := range strings.Fields(string(out)) {
		live = append(live, canonicalEntry(l))
	}
	sort.Strings(expected)
	sort.Strings(live)
	return DriftResult{InSync: slices.Equal(expected, live), Expected: expected, Live: live}, nil
}

// canonicalEntry makes "192.0.2.1/32" and pfctl's "192.0.2.1" compare equal.
func canonicalEntry(s string) string {
	if a, ok := strings.CutSuffix(s, "/32"); ok && !strings.Contains(a, ":") {
		return a
	}
	if a, ok := strings.CutSuffix(s, "/128"); ok && strings.Contains(a, ":") {
		return a
	}
	return s
}

// --- mutations ------------------------------------------------------------

func (s *Server) checkPre(exists bool, etag string, pre Precondition) error {
	switch {
	case exists && pre.IfNoneMatch:
		return errf(CodePrecondition, "object exists")
	case exists && pre.IfMatch != etag:
		return errf(CodePrecondition, msgETagMismatch, etag)
	case !exists && pre.IfMatch != "":
		return errf(CodePrecondition, "object does not exist")
	case !exists && !pre.IfNoneMatch:
		return errf(CodePrecondition, "creating needs If-None-Match: *")
	}
	return nil
}

func (s *Server) begin(c *change) ChangeInfo {
	c.info.ID = newID()
	c.info.Deadline = s.now().Add(s.cfg.ConfirmTimeout)
	id := c.info.ID
	c.timer = s.after(s.cfg.ConfirmTimeout, func() { s.expire(id) })
	s.pend = c
	s.log.Info("change applied, awaiting confirmation",
		"change", id, "actor", c.info.Actor, "kind", c.info.Kind, "name", c.info.Name,
		"op", c.info.Op, "deadline", c.info.Deadline)
	return c.info
}

func (s *Server) PutAnchor(ctx context.Context, actor string, a model.Anchor, pre Precondition) (ChangeInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pend != nil {
		return ChangeInfo{}, errf(CodeConflict, msgChangePending, s.pend.info.ID)
	}
	if err := a.Validate(s.cfg.Policy); err != nil {
		return ChangeInfo{}, AsError(err)
	}
	cur, err := s.st.GetAnchor(a.Name)
	exists := err == nil
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return ChangeInfo{}, err
	}
	etag := ""
	if exists {
		etag = store.ETag(cur)
	}
	if err := s.checkPre(exists, etag, pre); err != nil {
		return ChangeInfo{}, err
	}
	if err := s.loadAnchor(ctx, a); err != nil {
		return ChangeInfo{}, AsError(err)
	}
	if err := s.writeInclude(); err != nil {
		return ChangeInfo{}, err
	}
	next := a
	c := &change{info: ChangeInfo{Actor: actor, Kind: "anchor", Name: a.Name, Op: "put", ETag: store.ETag(a)}, nextAnch: &next}
	if exists {
		c.prevAnch = &cur
	}
	return s.begin(c), nil
}

func (s *Server) DeleteAnchor(ctx context.Context, actor, name string, pre Precondition) (ChangeInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pend != nil {
		return ChangeInfo{}, errf(CodeConflict, msgChangePending, s.pend.info.ID)
	}
	if !model.ValidName(name) {
		return ChangeInfo{}, errf(CodeInvalid, msgAnchorName, name)
	}
	cur, err := s.st.GetAnchor(name)
	if errors.Is(err, store.ErrNotFound) {
		return ChangeInfo{}, errf(CodeNotFound, msgAnchorNotFound, name)
	}
	if err != nil {
		return ChangeInfo{}, err
	}
	if pre.IfMatch != store.ETag(cur) {
		return ChangeInfo{}, errf(CodePrecondition, msgETagMismatch, store.ETag(cur))
	}
	if err := s.removeAnchor(ctx, name); err != nil {
		return ChangeInfo{}, AsError(err)
	}
	if err := s.writeInclude(); err != nil {
		return ChangeInfo{}, err
	}
	c := &change{info: ChangeInfo{Actor: actor, Kind: "anchor", Name: name, Op: "delete"}, prevAnch: &cur}
	return s.begin(c), nil
}

func (s *Server) PutTable(ctx context.Context, actor string, t model.Table, pre Precondition) (ChangeInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pend != nil {
		return ChangeInfo{}, errf(CodeConflict, msgChangePending, s.pend.info.ID)
	}
	if err := t.Validate(s.cfg.Policy); err != nil {
		return ChangeInfo{}, AsError(err)
	}
	cur, err := s.st.GetTable(t.Name)
	exists := err == nil
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return ChangeInfo{}, err
	}
	if !exists {
		cur = model.Table{Name: t.Name}
	}
	// Managed tables always exist (declared in the base ruleset), so a table
	// is "updated", never created: If-Match with the current ETag (which for
	// a never-written table is the ETag of the empty table).
	if pre.IfMatch != store.ETag(cur) {
		return ChangeInfo{}, errf(CodePrecondition, msgETagMismatch, store.ETag(cur))
	}
	if err := s.replaceTable(ctx, t); err != nil {
		return ChangeInfo{}, AsError(err)
	}
	prev, next := cur, t
	c := &change{info: ChangeInfo{Actor: actor, Kind: "table", Name: t.Name, Op: "put", ETag: store.ETag(t)}, prevTable: &prev, nextTable: &next}
	return s.begin(c), nil
}

func (s *Server) take(actor, id string, admin bool) (*change, error) {
	if s.pend == nil || s.pend.info.ID != id {
		return nil, errf(CodeNotFound, "no pending change %q", id)
	}
	if !admin && s.pend.info.Actor != actor {
		return nil, errf(CodeForbidden, "change %s belongs to %s", id, s.pend.info.Actor)
	}
	c := s.pend
	c.timer.Stop()
	s.pend = nil
	return c, nil
}

func raw(v any) json.RawMessage {
	if v == nil {
		return nil
	}
	b, _ := json.Marshal(v)
	return b
}

func (s *Server) history(c *change, outcome string) {
	h := store.HistoryEntry{ChangeID: c.info.ID, Actor: c.info.Actor, Kind: c.info.Kind, Name: c.info.Name, Outcome: outcome, Time: s.now()}
	switch c.info.Kind {
	case "anchor":
		if c.prevAnch != nil {
			h.Before = raw(c.prevAnch)
		}
		if c.nextAnch != nil {
			h.After = raw(c.nextAnch)
		}
	case "qos":
		h.Before, h.After = raw(c.prevQoS), raw(c.nextQoS)
	default:
		h.Before, h.After = raw(c.prevTable), raw(c.nextTable)
	}
	if err := s.st.AppendHistory(h); err != nil {
		s.log.Error("history write failed", "change", c.info.ID, "err", err)
	}
}

func (s *Server) Confirm(_ context.Context, actor, id string, admin bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.take(actor, id, admin)
	if err != nil {
		return err
	}
	switch {
	case c.info.Kind == "anchor" && c.nextAnch != nil:
		err = s.st.PutAnchor(*c.nextAnch)
	case c.info.Kind == "anchor":
		err = s.st.DeleteAnchor(c.info.Name)
	case c.info.Kind == "qos":
		err = s.st.PutQoS(*c.nextQoS)
	default:
		err = s.st.PutTable(*c.nextTable)
	}
	if err != nil {
		// Applied but not recorded: undo, so kernel and store stay equal.
		s.log.Error("store write failed on confirm; rolling back", "change", id, "err", err)
		if rerr := s.revert(context.Background(), c); rerr != nil {
			s.history(c, "revert_failed")
			return errf(CodeInternal, "store write failed (%v) and rollback failed (%v); reconcile needed", err, rerr)
		}
		s.history(c, "rolled_back")
		return errf(CodeInternal, "store write failed, change rolled back: %v", err)
	}
	s.history(c, "confirmed")
	s.log.Info("change confirmed", "change", id, "actor", actor, "kind", c.info.Kind, "name", c.info.Name)
	return nil
}

func (s *Server) Rollback(ctx context.Context, actor, id string, admin bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, err := s.take(actor, id, admin)
	if err != nil {
		return err
	}
	if err := s.revert(ctx, c); err != nil {
		return err
	}
	s.history(c, "rolled_back")
	return nil
}

func (s *Server) expire(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pend == nil || s.pend.info.ID != id {
		return // confirmed or rolled back in the meantime
	}
	c := s.pend
	s.pend = nil
	s.log.Warn("change not confirmed before deadline; rolling back", "change", id, "actor", c.info.Actor)
	if err := s.revert(context.Background(), c); err != nil {
		s.log.Error("automatic rollback failed", "change", id, "err", err)
	}
	s.history(c, "expired")
}

// revert restores the state from before c. Caller holds s.mu.
func (s *Server) revert(ctx context.Context, c *change) error {
	var err error
	switch {
	case c.info.Kind == "anchor" && c.prevAnch != nil:
		err = s.loadAnchor(ctx, *c.prevAnch)
	case c.info.Kind == "anchor":
		err = s.removeAnchor(ctx, c.info.Name)
	case c.info.Kind == "qos":
		err = s.applyQoS(ctx, *c.prevQoS)
	default:
		err = s.replaceTable(ctx, *c.prevTable)
	}
	if ierr := s.writeInclude(); ierr != nil && err == nil {
		err = ierr
	}
	if err != nil {
		s.log.Error("revert failed", "change", c.info.ID, "err", err)
		return AsError(err)
	}
	s.log.Info("change reverted", "change", c.info.ID, "kind", c.info.Kind, "name", c.info.Name)
	return nil
}

// Messages shared by the anchor, table and QoS operations.
const (
	msgAnchorName     = "anchor name %q"
	msgAnchorNotFound = "anchor %q"
	msgETagMismatch   = "ETag mismatch (have %s)"
	msgChangePending  = "change %s is pending"
)

// removeStrayAnchors deletes leftover .new files and unloads anchors whose
// file exists but which are not in the committed state.
func (s *Server) removeStrayAnchors(ctx context.Context, committed []string) ([]error, error) {
	ents, err := os.ReadDir(s.cfg.AnchorDir)
	if err != nil {
		return nil, err
	}
	var errs []error
	for _, e := range ents {
		n := e.Name()
		if strings.HasSuffix(n, ".new") {
			_ = os.Remove(filepath.Join(s.cfg.AnchorDir, n))
			continue
		}
		if name, ok := strings.CutSuffix(n, ".conf"); ok && model.ValidName(name) && !slices.Contains(committed, name) {
			s.log.Warn("removing anchor that is not in the committed state", "anchor", name)
			if err := s.removeAnchor(ctx, name); err != nil {
				errs = append(errs, fmt.Errorf("anchor %s: %w", name, err))
			}
		}
	}
	return errs, nil
}

// reloadAnchors loads every committed anchor again.
func (s *Server) reloadAnchors(ctx context.Context, committed []string) []error {
	var errs []error
	for _, name := range committed {
		a, err := s.st.GetAnchor(name)
		if err == nil {
			err = s.loadAnchor(ctx, a)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("anchor %s: %w", name, err))
		}
	}
	return errs
}

// reloadTables replaces the contents of every committed, still managed
// table.
func (s *Server) reloadTables(ctx context.Context) ([]error, error) {
	tables, err := s.st.ListTables()
	if err != nil {
		return nil, err
	}
	var errs []error
	for _, name := range tables {
		if !slices.Contains(s.cfg.Policy.Tables, name) {
			continue // no longer managed: leave the kernel table alone
		}
		t, err := s.st.GetTable(name)
		if err == nil {
			err = s.replaceTable(ctx, t)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("table %s: %w", name, err))
		}
	}
	return errs, nil
}

// Reconcile makes the kernel and the anchor files match the committed
// store. It runs at startup, which also undoes any change that was pending
// when pfapid stopped.
func (s *Server) Reconcile(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	committed, err := s.st.ListAnchors()
	if err != nil {
		return err
	}
	errs, err := s.removeStrayAnchors(ctx, committed)
	if err != nil {
		return err
	}
	errs = append(errs, s.reloadAnchors(ctx, committed)...)
	if err := s.writeInclude(); err != nil {
		errs = append(errs, err)
	}
	if err := s.reconcileQoS(ctx); err != nil {
		errs = append(errs, fmt.Errorf("qos: %w", err))
	}
	terrs, err := s.reloadTables(ctx)
	if err != nil {
		return err
	}
	errs = append(errs, terrs...)
	return errors.Join(errs...)
}

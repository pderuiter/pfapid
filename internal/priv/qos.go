package priv

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/pderuiter/pfapid/internal/model"
	"github.com/pderuiter/pfapid/internal/pfctl"
	"github.com/pderuiter/pfapid/internal/render"
	"github.com/pderuiter/pfapid/internal/store"
)

// QoS is applied differently from anchors and tables: queue definitions only
// exist in the main ruleset, and `set queue` only resolves when its anchor is
// loaded by a main load (M0 T1/T1b). The base ruleset therefore carries two
// hooks:
//
//	include "<QueueFile>"
//	anchor "api-qos"
//	load anchor "api-qos" from "<QoSFile>"
//
// and a QoS change rewrites both files and reloads the base ruleset. That
// reload is atomic and keeps runtime anchors and persist tables (M0 T5/T6).

func (s *Server) qosConfigured() bool {
	return s.cfg.QueueFile != "" && s.cfg.QoSFile != "" && s.cfg.BaseRuleset != ""
}

func (s *Server) qosEnabled() error {
	if !s.qosConfigured() {
		return errf(CodeNotFound, "QoS is not configured on this firewall")
	}
	return nil
}

// normQoS makes nil and empty lists identical, so ETags do not depend on how
// a client spelled "nothing".
func normQoS(q model.QoS) model.QoS {
	if q.Queues == nil {
		q.Queues = []model.Queue{}
	}
	if q.Rules == nil {
		q.Rules = []model.Rule{}
	}
	return q
}

func (s *Server) committedQoS() (model.QoS, error) {
	q, err := s.st.GetQoS()
	if errors.Is(err, store.ErrNotFound) {
		return normQoS(model.QoS{}), nil
	}
	return normQoS(q), err
}

func renderQoS(q model.QoS) (queues, rules []byte, err error) {
	if queues, err = render.QueueFile(q); err != nil {
		return nil, nil, errf(CodeInternal, "%v", err)
	}
	if rules, err = render.QoSAnchor(q); err != nil {
		return nil, nil, errf(CodeInternal, "%v", err)
	}
	return queues, rules, nil
}

// checkQoS runs pfctl -n twice: on a minimal main ruleset holding only the
// QoS files (its output is the normalised form drift compares against), and
// on a copy of the real base ruleset with the hooks pointed at the candidate
// files (does it still load as a whole?). Nothing is loaded.
func (s *Server) checkQoS(ctx context.Context, q model.QoS) (norm, rendered []string, err error) {
	qt, rt, err := renderQoS(q)
	if err != nil {
		return nil, nil, err
	}
	w := s.cfg.WorkDir
	qf, rf := filepath.Join(w, "qos-queues.check"), filepath.Join(w, "qos-rules.check")
	minimal, base := filepath.Join(w, "qos-main.check"), filepath.Join(w, "base.check")
	defer func() {
		for _, f := range []string{qf, rf, minimal, base} {
			_ = os.Remove(f)
		}
	}()
	for f, b := range map[string][]byte{qf: qt, rf: rt, minimal: qosMain(qf, rf)} {
		if err := store.WriteFileAtomic(f, b, 0o600); err != nil {
			return nil, nil, err
		}
	}
	out, err := s.pf.CheckMain(ctx, minimal)
	if err != nil {
		return nil, nil, errf(CodePFRejected, "%v", err)
	}
	baseText, err := os.ReadFile(s.cfg.BaseRuleset)
	if err != nil {
		return nil, nil, err
	}
	hookQ, hookR := quoted(s.cfg.QueueFile), quoted(s.cfg.QoSFile)
	if !bytes.Contains(baseText, []byte("include "+hookQ)) ||
		!bytes.Contains(baseText, []byte(`load anchor "`+pfctl.QoSAnchor+`" from `+hookR)) {
		return nil, nil, errf(CodeInternal, "base ruleset %s lacks the QoS hooks (include %s; load anchor %q from %s)",
			s.cfg.BaseRuleset, hookQ, pfctl.QoSAnchor, hookR)
	}
	candidate := strings.NewReplacer(hookQ, quoted(qf), hookR, quoted(rf)).Replace(string(baseText))
	if err := store.WriteFileAtomic(base, []byte(candidate), 0o600); err != nil {
		return nil, nil, err
	}
	if _, err := s.pf.CheckMain(ctx, base); err != nil {
		return nil, nil, errf(CodePFRejected, "base ruleset with these queues: %v", err)
	}
	rendered = append(pfctl.NormaliseRules(qt), pfctl.NormaliseRules(rt)...)
	return qosLines(out), rendered, nil
}

func quoted(path string) string { return `"` + path + `"` }

func qosMain(queueFile, rulesFile string) []byte {
	return []byte("include " + quoted(queueFile) + "\nanchor \"" + pfctl.QoSAnchor + "\"\nload anchor \"" +
		pfctl.QoSAnchor + "\" from " + quoted(rulesFile) + "\n")
}

// qosLines keeps the queue definitions and the anchor's rules from pfctl -nv
// output of qosMain, dropping the `anchor "api-qos" all` line itself.
func qosLines(out []byte) []string {
	var lines []string
	for _, l := range pfctl.NormaliseRules(out) {
		if strings.HasPrefix(l, "anchor ") {
			continue
		}
		lines = append(lines, l)
	}
	return lines
}

// applyQoS writes both QoS files and reloads the base ruleset. If the reload
// fails the kernel is unchanged (atomic load) and the old files are put back.
func (s *Server) applyQoS(ctx context.Context, q model.QoS) error {
	qt, rt, err := renderQoS(q)
	if err != nil {
		return err
	}
	old := map[string][]byte{}
	for _, f := range []string{s.cfg.QueueFile, s.cfg.QoSFile} {
		b, err := os.ReadFile(f) // #nosec G304 -- operator-configured path
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		old[f] = b
	}
	restore := func() {
		for f, b := range old {
			if b == nil {
				b = []byte{}
			}
			if err := store.WriteFileAtomic(f, b, 0o600); err != nil {
				s.log.Error("restoring QoS file failed", "file", f, "err", err)
			}
		}
	}
	if err := store.WriteFileAtomic(s.cfg.QueueFile, qt, 0o600); err != nil {
		return err
	}
	if err := store.WriteFileAtomic(s.cfg.QoSFile, rt, 0o600); err != nil {
		restore()
		return err
	}
	if err := s.pf.LoadMain(ctx); err != nil {
		restore()
		return errf(CodePFRejected, "%v", err)
	}
	return nil
}

func (s *Server) GetQoS(context.Context) (QoSState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.qosEnabled(); err != nil {
		return QoSState{}, err
	}
	q, err := s.committedQoS()
	if err != nil {
		return QoSState{}, err
	}
	return QoSState{QoS: q, ETag: store.ETag(q), PendingChange: s.pendingFor("qos", "qos")}, nil
}

func (s *Server) ValidateQoS(ctx context.Context, q model.QoS) (ValidateResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.qosEnabled(); err != nil {
		return ValidateResult{}, err
	}
	q = normQoS(q)
	if err := q.Validate(s.cfg.Policy); err != nil {
		return ValidateResult{}, AsError(err)
	}
	norm, rendered, err := s.checkQoS(ctx, q)
	if err != nil {
		return ValidateResult{}, err
	}
	return ValidateResult{Rendered: rendered, Normalised: norm}, nil
}

// PutQoS replaces the whole QoS document. Like a table it always exists
// (empty until first set), so it needs If-Match with the current ETag.
func (s *Server) PutQoS(ctx context.Context, actor string, q model.QoS, pre Precondition) (ChangeInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.qosEnabled(); err != nil {
		return ChangeInfo{}, err
	}
	if s.pend != nil {
		return ChangeInfo{}, errf(CodeConflict, msgChangePending, s.pend.info.ID)
	}
	q = normQoS(q)
	if err := q.Validate(s.cfg.Policy); err != nil {
		return ChangeInfo{}, AsError(err)
	}
	cur, err := s.committedQoS()
	if err != nil {
		return ChangeInfo{}, err
	}
	if pre.IfMatch != store.ETag(cur) {
		return ChangeInfo{}, errf(CodePrecondition, msgETagMismatch, store.ETag(cur))
	}
	if _, _, err := s.checkQoS(ctx, q); err != nil {
		return ChangeInfo{}, err
	}
	if err := s.applyQoS(ctx, q); err != nil {
		return ChangeInfo{}, AsError(err)
	}
	prev, next := cur, q
	c := &change{info: ChangeInfo{Actor: actor, Kind: "qos", Name: "qos", Op: "put", ETag: store.ETag(q)}, prevQoS: &prev, nextQoS: &next}
	return s.begin(c), nil
}

// DriftQoS compares the desired queues and rules (pending if a QoS change is
// pending, else committed) with pfctl -s queue and the api-qos anchor.
func (s *Server) DriftQoS(ctx context.Context) (DriftResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.qosEnabled(); err != nil {
		return DriftResult{}, err
	}
	want, err := s.committedQoS()
	if err != nil {
		return DriftResult{}, err
	}
	if s.pend != nil && s.pend.info.Kind == "qos" {
		want = *s.pend.nextQoS
	}
	expected, _, err := s.checkQoS(ctx, want)
	if err != nil {
		return DriftResult{}, err
	}
	qs, err := s.pf.Queues(ctx)
	if err != nil {
		return DriftResult{}, errf(CodePFRejected, "%v", err)
	}
	rs, err := s.pf.QoSRules(ctx)
	if err != nil {
		return DriftResult{}, errf(CodePFRejected, "%v", err)
	}
	live := append(pfctl.NormaliseRules(qs), pfctl.NormaliseRules(rs)...)
	return DriftResult{InSync: slices.Equal(expected, live), Expected: expected, Live: live}, nil
}

// reconcileQoS rewrites the QoS files from the committed store and reloads
// the base ruleset if they differ from what is on disk (a change that was
// pending when pfapid stopped, or missing files). Caller holds s.mu.
func (s *Server) reconcileQoS(ctx context.Context) error {
	if !s.qosConfigured() {
		return nil
	}
	q, err := s.committedQoS()
	if err != nil {
		return err
	}
	qt, rt, err := renderQoS(q)
	if err != nil {
		return err
	}
	diskQ, errQ := os.ReadFile(s.cfg.QueueFile)
	diskR, errR := os.ReadFile(s.cfg.QoSFile)
	if errQ == nil && errR == nil && bytes.Equal(diskQ, qt) && bytes.Equal(diskR, rt) {
		return nil
	}
	s.log.Warn("QoS files differ from the committed state; restoring and reloading the base ruleset")
	return s.applyQoS(ctx, q)
}

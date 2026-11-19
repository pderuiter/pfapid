package priv

import (
	"os"
	"strings"
	"testing"

	"github.com/pderuiter/pfapid/internal/model"
)

func qos(bulk string) model.QoS {
	return model.QoS{
		Queues: []model.Queue{
			{Name: "rootq", Interface: "vio1", Bandwidth: "100M", Max: "100M"},
			{Name: "std", Parent: "rootq", Bandwidth: "60M", Default: true},
			{Name: "bulk", Parent: "rootq", Bandwidth: bulk},
		},
		Rules: []model.Rule{{
			Action: model.Match, Direction: model.Out, Interface: "frontend", Family: model.Inet, Protocol: model.TCP,
			To: model.Endpoint{Ports: []model.PortRange{{From: 22}}}, Queue: &model.QueueSet{Name: "bulk"},
		}},
	}
}

func TestQoSPutConfirmDrift(t *testing.T) {
	h := newHarness(t)
	st, err := h.s.GetQoS(ctx)
	if err != nil || len(st.QoS.Queues) != 0 {
		t.Fatalf("initial: %+v %v", st, err)
	}
	if _, err := h.s.PutQoS(ctx, "tf", qos("20M"), Precondition{IfMatch: "stale"}); code(err) != CodePrecondition {
		t.Fatalf("stale etag: %v", err)
	}
	ci, err := h.s.PutQoS(ctx, "tf", qos("20M"), Precondition{IfMatch: st.ETag})
	if err != nil {
		t.Fatal(err)
	}
	if h.pf.mainLoads != 1 || !strings.Contains(h.pf.queues, "queue bulk parent rootq bandwidth 20M") ||
		!strings.Contains(h.pf.qos, "set queue bulk") {
		t.Fatalf("not loaded: %q %q", h.pf.queues, h.pf.qos)
	}
	if _, err := h.s.PutAnchor(ctx, "tf", anchor(443), Precondition{IfNoneMatch: true}); code(err) != CodeConflict {
		t.Fatalf("second change while QoS pending: %v", err)
	}
	if err := h.s.Confirm(ctx, "tf", ci.ID, false); err != nil {
		t.Fatal(err)
	}
	st, _ = h.s.GetQoS(ctx)
	if st.ETag != ci.ETag || len(st.QoS.Queues) != 3 {
		t.Fatalf("after confirm: %+v", st)
	}
	d, err := h.s.DriftQoS(ctx)
	if err != nil || !d.InSync {
		t.Fatalf("drift: %+v %v", d, err)
	}
	h.pf.queues += "queue extra parent rootq bandwidth 1M\n" // hand edit
	if d, _ := h.s.DriftQoS(ctx); d.InSync {
		t.Fatal("hand-added queue not reported as drift")
	}
}

func TestQoSExpiresAndRestoresFiles(t *testing.T) {
	h := newHarness(t)
	st, _ := h.s.GetQoS(ctx)
	ci, _ := h.s.PutQoS(ctx, "tf", qos("20M"), Precondition{IfMatch: st.ETag})
	_ = h.s.Confirm(ctx, "tf", ci.ID, false)
	st, _ = h.s.GetQoS(ctx)
	if _, err := h.s.PutQoS(ctx, "tf", qos("30M"), Precondition{IfMatch: st.ETag}); err != nil {
		t.Fatal(err)
	}
	h.expire()
	if !strings.Contains(h.pf.queues, "bandwidth 20M") || strings.Contains(h.pf.queues, "30M") {
		t.Fatalf("not rolled back: %s", h.pf.queues)
	}
	file, _ := os.ReadFile(h.pf.queueFile)
	if !strings.Contains(string(file), "bandwidth 20M") {
		t.Fatalf("queue file not restored: %s", file)
	}
}

func TestQoSRejectedLeavesEverything(t *testing.T) {
	h := newHarness(t)
	st, _ := h.s.GetQoS(ctx)
	h.pf.reject = "bandwidth 20M"
	if _, err := h.s.PutQoS(ctx, "tf", qos("20M"), Precondition{IfMatch: st.ETag}); code(err) != CodePFRejected {
		t.Fatalf("want pf_rejected, got %v", err)
	}
	if h.pf.mainLoads != 0 {
		t.Fatal("main ruleset reloaded although the check failed")
	}
	if p, _ := h.s.Pending(ctx); p != nil {
		t.Fatal("pending after reject")
	}
}

func TestQoSNeedsHooksInBase(t *testing.T) {
	h := newHarness(t)
	if err := os.WriteFile(h.s.cfg.BaseRuleset, []byte("pass\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.s.ValidateQoS(ctx, qos("20M")); err == nil || !strings.Contains(err.Error(), "QoS hooks") {
		t.Fatalf("missing hooks not reported: %v", err)
	}
}

func TestQoSReconcileUndoesUnconfirmed(t *testing.T) {
	h := newHarness(t)
	st, _ := h.s.GetQoS(ctx)
	_, _ = h.s.PutQoS(ctx, "tf", qos("20M"), Precondition{IfMatch: st.ETag})
	// Restart while pending: the committed QoS is empty.
	h2 := newHarness(t)
	h2.s.cfg, h2.s.st, h2.pf.queueFile, h2.pf.qosFile = h.s.cfg, h.s.st, h.pf.queueFile, h.pf.qosFile
	if err := h2.s.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	if h2.pf.mainLoads != 1 || strings.Contains(h2.pf.queues, "queue ") {
		t.Fatalf("unconfirmed queues survived restart: %q", h2.pf.queues)
	}
	// A second reconcile with matching files does not reload.
	if err := h2.s.Reconcile(ctx); err != nil || h2.pf.mainLoads != 1 {
		t.Fatalf("needless reload: %d %v", h2.pf.mainLoads, err)
	}
}

func TestQoSDisabled(t *testing.T) {
	h := newHarness(t)
	h.s.cfg.QueueFile = ""
	if _, err := h.s.GetQoS(ctx); code(err) != CodeNotFound {
		t.Fatalf("want not_found, got %v", err)
	}
}

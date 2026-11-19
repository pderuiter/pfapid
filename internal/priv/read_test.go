package priv

import (
	"strings"
	"testing"

	"github.com/pderuiter/pfapid/internal/model"
)

func TestListsAndValidate(t *testing.T) {
	h := newHarness(t)
	names, err := h.s.ListAnchors(ctx)
	if err != nil || len(names) != 0 {
		t.Fatalf("empty list: %v %v", names, err)
	}
	ci, err := h.s.PutAnchor(ctx, "tf", anchor(443), Precondition{IfNoneMatch: true})
	if err != nil {
		t.Fatal(err)
	}
	// Pending changes are not committed, so they are not listed yet.
	if names, _ := h.s.ListAnchors(ctx); len(names) != 0 {
		t.Fatalf("pending anchor listed: %v", names)
	}
	if err := h.s.Confirm(ctx, "tf", ci.ID, false); err != nil {
		t.Fatal(err)
	}
	if names, _ := h.s.ListAnchors(ctx); len(names) != 1 || names[0] != "k8s-prod" {
		t.Fatalf("list after confirm: %v", names)
	}

	tables, err := h.s.ListTables(ctx)
	if err != nil || len(tables) != 1 || tables[0] != "k8s_nodes" {
		t.Fatalf("tables: %v %v", tables, err)
	}
	tables[0] = "mutated"
	if again, _ := h.s.ListTables(ctx); again[0] != "k8s_nodes" {
		t.Fatal("ListTables exposes the policy slice")
	}

	// Validate is a dry run: rendered + normalised, nothing loaded.
	loaded := len(h.pf.anchors)
	res, err := h.s.ValidateAnchor(ctx, anchor(8443))
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Rendered) != 1 || !strings.Contains(res.Rendered[0], "8443") || len(res.Normalised) != 1 {
		t.Fatalf("validate: %+v", res)
	}
	if len(h.pf.anchors) != loaded || strings.Contains(h.pf.anchors["k8s-prod"], "8443") {
		t.Fatalf("validate loaded rules: %v", h.pf.anchors)
	}

	bad := anchor(443)
	bad.Rules[0].Interface = "mgmt"
	if _, err := h.s.ValidateAnchor(ctx, bad); code(err) != CodeInvalid {
		t.Fatalf("invalid anchor: %v", err)
	}
	h.pf.reject = "8443"
	if _, err := h.s.ValidateAnchor(ctx, anchor(8443)); code(err) != CodePFRejected {
		t.Fatalf("pfctl rejection: %v", err)
	}
	if _, err := h.s.ValidateAnchor(ctx, model.Anchor{Name: "Bad"}); code(err) != CodeInvalid {
		t.Fatalf("bad name: %v", err)
	}
}

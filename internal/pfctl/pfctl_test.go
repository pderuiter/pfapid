package pfctl

import (
	"context"
	"errors"
	"testing"
)

func TestRefusedArguments(t *testing.T) {
	x := Exec{Path: "/nonexistent/pfctl", FileDirs: []string{"/etc/pf.anchors/api"}}
	ctx := context.Background()
	for _, err := range []error{
		x.LoadAnchor(ctx, "../etc", "/etc/pf.anchors/api/a.conf"),
		x.LoadAnchor(ctx, "a", "/etc/pf.conf"),
		x.LoadAnchor(ctx, "a", "/etc/pf.anchors/api/../../pf.conf"),
		x.LoadAnchor(ctx, "a", "relative.conf"),
		x.ReplaceTable(ctx, "t; rm", "/etc/pf.anchors/api/t"),
		x.FlushAnchor(ctx, "A B"),
	} {
		if !errors.Is(err, errArg) {
			t.Errorf("want refused argument, got %v", err)
		}
	}
}

func TestNormaliseRules(t *testing.T) {
	in := "web_ports = \"{ 80 443 }\"\n\npass  in on frontend   inet proto tcp from any to any port = 80 flags S/SA\n# c\n"
	got := NormaliseRules([]byte(in))
	if len(got) != 1 || got[0] != "pass in on frontend inet proto tcp from any to any port = 80 flags S/SA" {
		t.Fatalf("%q", got)
	}
}

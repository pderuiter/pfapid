package render

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"

	"github.com/pderuiter/pfapid/internal/model"
)

var pol = model.Policy{
	Interfaces: []string{"frontend", "backend"},
	Tables:     []string{"k8s_nodes"},
	RefTables:  []string{"rfc1918"},
}

func p(s string) netip.Prefix   { return netip.MustParsePrefix(s) }
func pp(s string) *netip.Prefix { v := p(s); return &v }
func u8(v uint8) *uint8         { return &v }

// Golden lines. Their syntax was loaded with pfctl on the OpenBSD 7.9 lab
// (M0 T3/T10b) or is the documented pf.conf form.
func TestRuleGolden(t *testing.T) {
	cases := []struct {
		r    model.Rule
		want string
	}{
		{model.Rule{Action: model.Pass, Direction: model.In, Quick: true, Interface: "frontend", Family: model.Inet, Protocol: model.TCP,
			To: model.Endpoint{Table: "k8s_nodes", Ports: []model.PortRange{{From: 80}, {From: 443}}}},
			"pass in quick on frontend inet proto tcp from any to <k8s_nodes> port { 80 443 }"},
		{model.Rule{Action: model.Match, Direction: model.Out, Interface: "frontend", Family: model.Inet,
			From: model.Endpoint{Prefixes: []netip.Prefix{p("10.70.1.0/24")}}, NAT: &model.NAT{Kind: model.NATTo, Interface: "frontend"}},
			"match out on frontend inet from 10.70.1.0/24 to any nat-to (frontend:0)"},
		{model.Rule{Action: model.Match, Direction: model.In, Interface: "frontend", Family: model.Inet6, Protocol: model.TCP,
			To:  model.Endpoint{Prefixes: []netip.Prefix{p("2001:db8:f::1/128")}, Ports: []model.PortRange{{From: 8443}}},
			NAT: &model.NAT{Kind: model.RdrTo, Address: pp("fd00:b::225/128"), Port: &model.PortRange{From: 443}}},
			"match in on frontend inet6 proto tcp from any to 2001:db8:f::1/128 port 8443 rdr-to fd00:b::225/128 port 443"},
		{model.Rule{Action: model.Pass, Direction: model.In, Interface: "backend", Family: model.Inet6,
			From: model.Endpoint{Prefixes: []netip.Prefix{p("fd00:b::/64")}}, To: model.Endpoint{Prefixes: []netip.Prefix{p("64:ff9b::/96")}},
			NAT: &model.NAT{Kind: model.AFTo, ToFamily: model.Inet, AFFrom: pp("203.0.113.5/32")}},
			"pass in on backend inet6 from fd00:b::/64 to 64:ff9b::/96 af-to inet from 203.0.113.5/32"},
		{model.Rule{Action: model.Block, BlockReturn: true, Direction: model.In, Log: true, Interface: "backend", Family: model.Inet6},
			"block return in log on backend inet6 from any to any"},
		{model.Rule{Action: model.Pass, Direction: model.In, Interface: "backend", Family: model.Inet, Protocol: model.TCP,
			To:   model.Endpoint{Ports: []model.PortRange{{From: 1024, To: 65535}}},
			Prio: &model.Prio{Normal: 2, Low: u8(6)}, Label: "ssh-in"},
			`pass in on backend inet proto tcp from any to any port 1024:65535 set prio (2, 6) label "ssh-in"`},
		// Negation, self and icmp-type: the pf.conf(5) forms wbyc-fw01's base
		// ruleset uses today (pass in on $vm_ifs ... to !<rfc1918>, to self
		// icmp-type echoreq).
		{model.Rule{Action: model.Pass, Direction: model.In, Interface: "frontend", Family: model.Inet,
			From: model.Endpoint{Table: "k8s_nodes"}, To: model.Endpoint{Negate: true, Table: "rfc1918"}},
			"pass in on frontend inet from <k8s_nodes> to ! <rfc1918>"},
		{model.Rule{Action: model.Pass, Direction: model.In, Interface: "frontend", Family: model.Inet, Protocol: model.ICMP,
			From: model.Endpoint{Table: "k8s_nodes"}, To: model.Endpoint{Self: true}, ICMPTypes: []string{"echoreq"}},
			"pass in on frontend inet proto icmp from <k8s_nodes> to self icmp-type echoreq"},
		{model.Rule{Action: model.Pass, Direction: model.In, Interface: "backend", Family: model.Inet6, Protocol: model.ICMP6,
			From: model.Endpoint{Negate: true, Prefixes: []netip.Prefix{p("fd00::/8")}}, To: model.Endpoint{Negate: true, Interface: "backend"},
			ICMPTypes: []string{"echoreq", "128"}, Label: "ping6"},
			`pass in on backend inet6 proto icmp6 from ! fd00::/8 to ! (backend) icmp6-type { echoreq 128 } label "ping6"`},
		{model.Rule{Action: model.Block, Direction: model.In, Quick: true, Interface: "backend", Family: model.Inet, Protocol: model.TCP,
			From: model.Endpoint{Negate: true, Self: true}, To: model.Endpoint{Self: true, Ports: []model.PortRange{{From: 22}}}},
			"block in quick on backend inet proto tcp from ! self to self port 22"},
	}
	for _, c := range cases {
		if err := c.r.Validate(pol); err != nil {
			t.Fatalf("fixture invalid: %v", err)
		}
		if got := Rule(c.r); got != c.want {
			t.Errorf("\n got %s\nwant %s", got, c.want)
		}
	}
}

func TestGuard(t *testing.T) {
	ok := []byte(header + "pass in on frontend inet from any to any label \"queue table\"\n")
	if err := Guard(ok, 1); err != nil {
		t.Fatalf("label words must be allowed: %v", err)
	}
	bad := []string{
		"include \"/etc/pf.conf\"",
		"anchor \"x\" {",
		"pass in on frontend inet from any to any\npass all",
		"table <x> persist",
		"x = \"1\"",
		"pass in on frontend inet from any to any label \"a\" label \"b\"",
		"pass \"x\" in on frontend",
		"load anchor \"x\" from \"/tmp/x\"",
		"pass in on frontend inet from any to any \\",
	}
	for _, b := range bad {
		if err := Guard([]byte(header+b+"\n"), 1); err == nil {
			t.Errorf("guard accepted %q", b)
		}
	}
	if err := Guard([]byte("pass all\n"), 1); err == nil {
		t.Error("guard accepted output without header")
	}
}

// FuzzAnchor: whatever JSON arrives, an anchor that passes validation must
// render to exactly one guarded line per rule. A render guard failure on a
// validated anchor is a validation bug (an injection path).
func FuzzAnchor(f *testing.F) {
	seeds := []string{
		`{"name":"a","rules":[{"action":"pass","direction":"in","interface":"frontend","family":"inet","protocol":"tcp","from":{},"to":{"table":"k8s_nodes","ports":[{"from":443}]}}]}`,
		`{"name":"a","rules":[{"action":"pass","interface":"frontend","family":"inet","from":{},"to":{},"label":"x\" pass all"}]}`,
		`{"name":"a","rules":[{"action":"match","direction":"out","interface":"frontend","family":"inet6","from":{"prefixes":["fd00::/8"]},"to":{},"nat":{"kind":"nat-to","interface":"frontend"}}]}`,
		`{"name":"a\nb","rules":[]}`,
		`{"name":"a","rules":[{"action":"pass","interface":"front\nend","family":"inet","from":{},"to":{}}]}`,
		`{"name":"a","rules":[{"action":"pass","direction":"in","interface":"frontend","family":"inet","from":{"table":"k8s_nodes"},"to":{"negate":true,"table":"rfc1918"}}]}`,
		`{"name":"a","rules":[{"action":"pass","interface":"frontend","family":"inet","protocol":"icmp","from":{},"to":{"self":true},"icmp_types":["echoreq","3"]}]}`,
		`{"name":"a","rules":[{"action":"pass","interface":"frontend","family":"inet","protocol":"icmp","from":{},"to":{},"icmp_types":["echoreq\npass all"]}]}`,
	}
	for _, s := range seeds {
		f.Add([]byte(s))
	}
	fuzzPol := model.Policy{Interfaces: []string{"frontend", "backend"}, Tables: []string{"k8s_nodes"}, RefTables: []string{"rfc1918"}}
	f.Fuzz(func(t *testing.T, data []byte) {
		var a model.Anchor
		if json.Unmarshal(data, &a) != nil {
			return
		}
		if a.Validate(fuzzPol) != nil {
			return
		}
		out, err := Anchor(a)
		if err != nil {
			t.Fatalf("validated anchor failed the render guard: %v\n%s", err, data)
		}
		if n := strings.Count(string(out), "\n"); n != len(a.Rules)+1 {
			t.Fatalf("%d lines for %d rules", n, len(a.Rules))
		}
	})
}

func TestIncludeFile(t *testing.T) {
	got := string(IncludeFile("/etc/pf.anchors/api", []string{"a", "k8s-prod"}))
	want := header + "load anchor \"api/a\" from \"/etc/pf.anchors/api/a.conf\"\nload anchor \"api/k8s-prod\" from \"/etc/pf.anchors/api/k8s-prod.conf\"\n"
	if got != want {
		t.Fatalf("got\n%s", got)
	}
}

func TestQoSRender(t *testing.T) {
	q := model.QoS{
		Queues: []model.Queue{
			{Name: "rootq", Interface: "vio1", Bandwidth: "100M", Max: "100M"},
			{Name: "std", Parent: "rootq", Bandwidth: "60M", Default: true},
			{Name: "fq", Parent: "rootq", Bandwidth: "20M", Flows: 1024, Quantum: 1500, QLimit: 50},
		},
		Rules: []model.Rule{{Action: model.Match, Direction: model.Out, Interface: "frontend", Family: model.Inet6,
			Prio: &model.Prio{Normal: 3}, Queue: &model.QueueSet{Name: "fq", Priority: "std"}, Label: "voip"}},
	}
	qf, err := QueueFile(q)
	if err != nil {
		t.Fatal(err)
	}
	want := header + "queue rootq on vio1 bandwidth 100M max 100M\n" +
		"queue std parent rootq bandwidth 60M default\n" +
		"queue fq parent rootq bandwidth 20M flows 1024 quantum 1500 qlimit 50\n"
	if string(qf) != want {
		t.Fatalf("queue file:\n%s", qf)
	}
	rf, err := QoSAnchor(q)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(rf), "match out on frontend inet6 from any to any set prio 3 set queue (fq, std) label \"voip\"\n") {
		t.Fatalf("rules:\n%s", rf)
	}
	// The normal anchor guard still refuses set queue.
	if err := Guard(rf, 1); err == nil {
		t.Fatal("Guard accepted set queue")
	}
	// A queue line that is not a queue definition is refused.
	bad := q
	bad.Queues = []model.Queue{{Name: "x", Interface: "vio1", Bandwidth: "1M\npass all"}}
	if _, err := QueueFile(bad); err == nil {
		t.Fatal("injected line accepted")
	}
}

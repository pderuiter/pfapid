package model

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

var pol = Policy{
	Interfaces:   []string{"frontend", "backend", "vlan910"},
	Tables:       []string{"k8s_nodes"},
	InternalNets: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("192.168.2.0/24"), netip.MustParsePrefix("fd00::/8")},
}

func pfx(s string) []netip.Prefix { return []netip.Prefix{netip.MustParsePrefix(s)} }
func ptr[T any](v T) *T           { return &v }

func base() Rule {
	return Rule{Action: Pass, Direction: In, Interface: "frontend", Family: Inet, Protocol: TCP,
		To: Endpoint{Table: "k8s_nodes", Ports: []PortRange{{From: 443}}}}
}

func TestRuleValidate(t *testing.T) {
	cases := []struct {
		name string
		mod  func(*Rule)
		want string // substring of the error, "" = valid
	}{
		{"valid", func(*Rule) {}, ""},
		{"mgmt interface refused", func(r *Rule) { r.Interface = "mgmt" }, "interface"},
		{"unknown interface", func(r *Rule) { r.Interface = "vio0" }, "interface"},
		{"no family", func(r *Rule) { r.Family = "" }, "family"},
		{"v6 prefix in inet rule", func(r *Rule) { r.From.Prefixes = pfx("2001:db8::/32") }, "is not inet"},
		{"host bits", func(r *Rule) { r.From.Prefixes = pfx("10.1.2.3/8") }, "host bits"},
		{"4in6", func(r *Rule) { r.Family = Inet6; r.From.Prefixes = pfx("::ffff:10.0.0.0/104") }, "IPv4-mapped"},
		{"unknown table", func(r *Rule) { r.To.Table = "nope" }, "not a managed table"},
		{"ports without tcp/udp", func(r *Rule) { r.Protocol = AnyProto }, "ports need"},
		{"port 0", func(r *Rule) { r.To.Ports = []PortRange{{From: 0}} }, "port 0"},
		{"descending range", func(r *Rule) { r.To.Ports = []PortRange{{From: 100, To: 50}} }, "ascending"},
		{"two address kinds", func(r *Rule) { r.To.Prefixes = pfx("10.0.0.0/8") }, "only one"},
		{"icmp in inet6", func(r *Rule) { r.Family = Inet6; r.Protocol = ICMP; r.To = Endpoint{} }, "icmp needs"},
		{"label injection quote", func(r *Rule) { r.Label = `x" pass all` }, "label"},
		{"label newline", func(r *Rule) { r.Label = "a\nb" }, "label"},
		{"match quick", func(r *Rule) { r.Action = Match; r.Quick = true }, "quick"},
		{"block return on pass", func(r *Rule) { r.BlockReturn = true }, "block_return"},
		{"prio 8", func(r *Rule) { r.Prio = &Prio{Normal: 8} }, "prio"},
		{"bad action", func(r *Rule) { r.Action = "scrub" }, "action"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := base()
			c.mod(&r)
			err := r.Validate(pol)
			if c.want == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), c.want) || !errors.Is(err, ErrInvalid) {
				t.Fatalf("want error containing %q, got %v", c.want, err)
			}
		})
	}
}

func TestNATValidate(t *testing.T) {
	ext := netip.MustParsePrefix("203.0.113.5/32")
	cases := []struct {
		name string
		r    Rule
		want string
	}{
		{"egress nat-to interface", Rule{Action: Match, Direction: Out, Interface: "frontend", Family: Inet,
			From: Endpoint{Prefixes: pfx("10.70.1.0/24")}, NAT: &NAT{Kind: NATTo, Interface: "frontend"}}, ""},
		{"internal to internal refused", Rule{Action: Match, Direction: Out, Interface: "frontend", Family: Inet,
			From: Endpoint{Prefixes: pfx("10.70.1.0/24")}, To: Endpoint{Prefixes: pfx("192.168.2.0/24")},
			NAT: &NAT{Kind: NATTo, Interface: "frontend"}}, "both internal"},
		{"rdr-to with port", Rule{Action: Match, Direction: In, Interface: "frontend", Family: Inet, Protocol: TCP,
			To:  Endpoint{Interface: "frontend", Ports: []PortRange{{From: 8443}}},
			NAT: &NAT{Kind: RdrTo, Address: ptr(netip.MustParsePrefix("10.70.1.225/32")), Port: &PortRange{From: 443}}}, ""},
		{"rdr-to port without proto", Rule{Action: Match, Direction: In, Interface: "frontend", Family: Inet,
			NAT: &NAT{Kind: RdrTo, Address: &ext, Port: &PortRange{From: 443}}}, "rdr-to port needs"},
		{"nat-to wrong family", Rule{Action: Match, Direction: Out, Interface: "frontend", Family: Inet6,
			NAT: &NAT{Kind: NATTo, Address: &ext}}, "is not inet6"},
		{"binat same length", Rule{Action: Match, Interface: "frontend", Family: Inet6, From: Endpoint{Prefixes: pfx("fd00:b::/64")},
			NAT: &NAT{Kind: BinatTo, Address: ptr(netip.MustParsePrefix("2001:db8:f:100::/64"))}}, ""},
		{"binat length mismatch (pfctl accepts this, M0 T10c)", Rule{Action: Match, Interface: "frontend", Family: Inet6, From: Endpoint{Prefixes: pfx("fd00:b::/64")},
			NAT: &NAT{Kind: BinatTo, Address: ptr(netip.MustParsePrefix("2001:db8:f::/56"))}}, "prefix lengths differ"},
		{"nat64", Rule{Action: Pass, Direction: In, Interface: "backend", Family: Inet6, To: Endpoint{Prefixes: pfx("64:ff9b::/96")},
			NAT: &NAT{Kind: AFTo, ToFamily: Inet, AFFrom: ptr(netip.MustParsePrefix("203.0.113.5/32"))}}, ""},
		{"af-to on match", Rule{Action: Match, Direction: In, Interface: "backend", Family: Inet6,
			NAT: &NAT{Kind: AFTo, ToFamily: Inet, AFFrom: &ext}}, "only on pass in"},
		{"af-to same family", Rule{Action: Pass, Direction: In, Interface: "backend", Family: Inet,
			NAT: &NAT{Kind: AFTo, ToFamily: Inet, AFFrom: &ext}}, "must differ"},
		{"nat on block", Rule{Action: Block, Interface: "backend", Family: Inet, NAT: &NAT{Kind: NATTo, Address: &ext}}, "block"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.r.Validate(pol)
			if c.want == "" && err != nil {
				t.Fatalf("unexpected: %v", err)
			}
			if c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)) {
				t.Fatalf("want %q, got %v", c.want, err)
			}
		})
	}
}

func TestAllowInternalNAT(t *testing.T) {
	r := Rule{Action: Match, Direction: Out, Interface: "frontend", Family: Inet,
		From: Endpoint{Prefixes: pfx("10.70.1.0/24")}, To: Endpoint{Prefixes: pfx("10.69.0.0/16")},
		NAT: &NAT{Kind: NATTo, Interface: "frontend"}}
	p := pol
	p.AllowInternalNAT = true
	if err := r.Validate(p); err != nil {
		t.Fatal(err)
	}
}

func TestAnchorAndTable(t *testing.T) {
	if err := (Anchor{Name: "Bad Name"}).Validate(pol); err == nil {
		t.Fatal("bad name accepted")
	}
	if err := (Anchor{Name: "../x"}).Validate(pol); err == nil {
		t.Fatal("path name accepted")
	}
	p := pol
	p.MaxRules = 1
	if err := (Anchor{Name: "a", Rules: []Rule{base(), base()}}).Validate(p); err == nil {
		t.Fatal("rule limit not enforced")
	}
	tb := Table{Name: "k8s_nodes", Entries: []netip.Prefix{netip.MustParsePrefix("10.0.0.1/32"), netip.MustParsePrefix("2001:db8::1/128")}}
	if err := tb.Validate(pol); err != nil {
		t.Fatalf("mixed-family table: %v", err)
	}
	tb.Entries = append(tb.Entries, netip.MustParsePrefix("10.0.0.1/32"))
	if err := tb.Validate(pol); err == nil {
		t.Fatal("duplicate accepted")
	}
	if err := (Table{Name: "other"}).Validate(pol); err == nil {
		t.Fatal("unmanaged table accepted")
	}
}

func TestPolicyValidate(t *testing.T) {
	if err := (Policy{Interfaces: []string{"mgmt"}}).Validate(); err == nil {
		t.Fatal("mgmt in policy accepted")
	}
	if err := pol.Validate(); err != nil {
		t.Fatal(err)
	}
}

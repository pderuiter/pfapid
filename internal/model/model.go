// Package model holds the typed pf objects pfapid manages and their
// validation. Nothing outside this package's types ever reaches the
// renderer: every address is a netip value, every keyword an enum, and every
// name matches a strict pattern. That is the primary defence against
// pf.conf injection (see docs/DESIGN.md §6.2).
package model

import (
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// Family is an address family. Every rule names exactly one: pfctl silently
// expands a mixed-family rule into one rule per family (M0 T10a), which would
// break the object <-> rule mapping. Use a table for dual-stack rules: a rule
// referencing a mixed table stays one rule (M0 T10e).
type Family string

const (
	Inet  Family = "inet"
	Inet6 Family = "inet6"
)

type Action string

const (
	Pass  Action = "pass"
	Block Action = "block"
	Match Action = "match"
)

type Direction string

const (
	In   Direction = "in"
	Out  Direction = "out"
	Both Direction = ""
)

type Protocol string

const (
	AnyProto Protocol = ""
	TCP      Protocol = "tcp"
	UDP      Protocol = "udp"
	ICMP     Protocol = "icmp"
	ICMP6    Protocol = "icmp6"
)

type NATKind string

const (
	NATTo   NATKind = "nat-to"
	RdrTo   NATKind = "rdr-to"
	BinatTo NATKind = "binat-to"
	AFTo    NATKind = "af-to"
)

// PortRange is a single port (To == 0) or an inclusive range From..To.
type PortRange struct {
	From uint16 `json:"from"`
	To   uint16 `json:"to,omitempty"`
}

// Endpoint is one side of a rule. At most one of Prefixes, Table and
// Interface is set; none means "any".
type Endpoint struct {
	Prefixes  []netip.Prefix `json:"prefixes,omitempty"`
	Table     string         `json:"table,omitempty"`
	Interface string         `json:"interface,omitempty"` // the interface's own addresses: (name)
	Ports     []PortRange    `json:"ports,omitempty"`
}

// NAT is the translation part of a match or pass rule.
type NAT struct {
	Kind NATKind `json:"kind"`
	// Target address for nat-to/rdr-to/binat-to. Exactly one of Address and
	// Interface (rendered as (name:0)).
	Address   *netip.Prefix `json:"address,omitempty"`
	Interface string        `json:"interface,omitempty"`
	Port      *PortRange    `json:"port,omitempty"` // rdr-to only
	// af-to: the translated family, its source and optional destination.
	ToFamily Family        `json:"to_family,omitempty"`
	AFFrom   *netip.Prefix `json:"af_from,omitempty"`
	AFTo     *netip.Prefix `json:"af_to,omitempty"`
}

// Prio is `set prio N` or `set prio (N, M)`.
type Prio struct {
	Normal uint8  `json:"normal"`
	Low    *uint8 `json:"low,omitempty"`
}

type Rule struct {
	Action      Action    `json:"action"`
	Direction   Direction `json:"direction,omitempty"`
	Quick       bool      `json:"quick,omitempty"`
	Log         bool      `json:"log,omitempty"`
	BlockReturn bool      `json:"block_return,omitempty"`
	Interface   string    `json:"interface"`
	Family      Family    `json:"family"`
	Protocol    Protocol  `json:"protocol,omitempty"`
	From        Endpoint  `json:"from"`
	To          Endpoint  `json:"to"`
	NAT         *NAT      `json:"nat,omitempty"`
	Prio        *Prio     `json:"prio,omitempty"`
	// Queue (`set queue`) is only valid in the QoS document (M0 T1b).
	Queue *QueueSet `json:"queue,omitempty"`
	Label string    `json:"label,omitempty"`
}

// Anchor is the unit of ownership and of atomic load: api/<Name>.
type Anchor struct {
	Name  string `json:"name"`
	Rules []Rule `json:"rules"`
}

// Table is a global table whose contents pfapid owns. The base ruleset
// declares it empty (`table <x> persist`) so that a reload of the base keeps
// the entries (M0 T6b).
type Table struct {
	Name    string         `json:"name"`
	Entries []netip.Prefix `json:"entries"`
}

// Policy is the operator-controlled envelope every object must fit in. It
// lives in the root-owned config and is enforced on the privileged side.
type Policy struct {
	// Interfaces / interface groups rules may name. The management group is
	// deliberately never in here: it is read-only for the API.
	Interfaces []string `json:"interfaces"`
	// Global tables (declared in the base ruleset) whose contents the API
	// manages and which rules may reference.
	Tables []string `json:"tables"`
	// Internal networks: NAT between two internal networks is refused unless
	// AllowInternalNAT (decision 2026-11-19: no NAT for internal traffic).
	InternalNets     []netip.Prefix `json:"internal_nets"`
	AllowInternalNAT bool           `json:"allow_internal_nat"`
	MaxRules         int            `json:"max_rules"`
	// Physical interfaces QoS queue trees may be attached to. pf needs a
	// real interface here, not a group (M0 T1c). Empty disables QoS.
	QueueInterfaces []string `json:"queue_interfaces,omitempty"`
	MaxTableEntries int      `json:"max_table_entries"`
}

var (
	nameRe  = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,30}$`)
	labelRe = regexp.MustCompile(`^[A-Za-z0-9 _.:/-]{0,63}$`)
)

// ValidName reports whether s is usable as an anchor, table or interface name.
func ValidName(s string) bool { return nameRe.MatchString(s) }

// ErrInvalid wraps every validation failure.
var ErrInvalid = errors.New("invalid")

func invalid(format string, a ...any) error {
	return fmt.Errorf("%w: %s", ErrInvalid, fmt.Sprintf(format, a...))
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func familyOf(p netip.Prefix) Family {
	if p.Addr().Is4() {
		return Inet
	}
	return Inet6
}

func checkPrefix(p netip.Prefix, fam Family, what string) error {
	if !p.IsValid() {
		return invalid("%s: invalid prefix", what)
	}
	if p.Addr().Is4In6() {
		return invalid("%s: IPv4-mapped IPv6 address %s is not allowed", what, p)
	}
	if p.Addr().Zone() != "" {
		return invalid("%s: zoned address %s is not allowed", what, p)
	}
	if p != p.Masked() {
		return invalid("%s: %s has host bits set (use %s)", what, p, p.Masked())
	}
	if familyOf(p) != fam {
		return invalid("%s: %s is not %s", what, p, fam)
	}
	return nil
}

func (pr PortRange) validate(what string) error {
	if pr.From == 0 {
		return invalid("%s: port 0", what)
	}
	if pr.To != 0 && pr.To <= pr.From {
		return invalid("%s: range %d:%d must be ascending", what, pr.From, pr.To)
	}
	return nil
}

func (e Endpoint) validate(what string, fam Family, proto Protocol, pol Policy) error {
	set := 0
	if len(e.Prefixes) > 0 {
		set++
	}
	if e.Table != "" {
		set++
	}
	if e.Interface != "" {
		set++
	}
	if set > 1 {
		return invalid("%s: use only one of prefixes, table, interface", what)
	}
	for _, p := range e.Prefixes {
		if err := checkPrefix(p, fam, what); err != nil {
			return err
		}
	}
	if e.Table != "" && !contains(pol.Tables, e.Table) {
		return invalid("%s: table %q is not a managed table", what, e.Table)
	}
	if e.Interface != "" && !contains(pol.Interfaces, e.Interface) {
		return invalid("%s: interface %q is not allowed", what, e.Interface)
	}
	if len(e.Ports) > 0 && proto != TCP && proto != UDP {
		return invalid("%s: ports need protocol tcp or udp", what)
	}
	for _, pr := range e.Ports {
		if err := pr.validate(what); err != nil {
			return err
		}
	}
	return nil
}

// insideAll reports whether every prefix lies inside one of nets. An
// endpoint that is "any", a table or an interface is not provably internal.
func insideAll(e Endpoint, nets []netip.Prefix) bool {
	if len(e.Prefixes) == 0 {
		return false
	}
	for _, p := range e.Prefixes {
		in := false
		for _, n := range nets {
			if n.Bits() <= p.Bits() && n.Contains(p.Addr()) {
				in = true
				break
			}
		}
		if !in {
			return false
		}
	}
	return true
}

func (n NAT) validate(r Rule, pol Policy) error {
	switch n.Kind {
	case NATTo, RdrTo, BinatTo:
		return n.validateTranslate(r, pol)
	case AFTo:
		return n.validateAFTo(r)
	default:
		return invalid("nat: unknown kind %q", n.Kind)
	}
}

// validateTranslate checks nat-to, rdr-to and binat-to.
func (n NAT) validateTranslate(r Rule, pol Policy) error {
	if (n.Address == nil) == (n.Interface == "") {
		return invalid("nat: set exactly one of address, interface")
	}
	if n.Address != nil {
		if err := checkPrefix(*n.Address, r.Family, "nat address"); err != nil {
			return err
		}
	}
	if n.Interface != "" && !contains(pol.Interfaces, n.Interface) {
		return invalid("nat: interface %q is not allowed", n.Interface)
	}
	if n.ToFamily != "" || n.AFFrom != nil || n.AFTo != nil {
		return invalid("nat: af-to fields only apply to af-to")
	}
	if err := n.validatePort(r); err != nil {
		return err
	}
	if err := n.validateBinat(r); err != nil {
		return err
	}
	if !pol.AllowInternalNAT && insideAll(r.From, pol.InternalNets) && insideAll(r.To, pol.InternalNets) {
		return invalid("nat: source and destination are both internal; internal traffic is routed, not translated")
	}
	return nil
}

func (n NAT) validatePort(r Rule) error {
	if n.Port == nil {
		return nil
	}
	if n.Kind != RdrTo {
		return invalid("nat: port only applies to rdr-to")
	}
	if r.Protocol != TCP && r.Protocol != UDP {
		return invalid("nat: rdr-to port needs protocol tcp or udp")
	}
	return n.Port.validate("nat port")
}

func (n NAT) validateBinat(r Rule) error {
	if n.Kind != BinatTo {
		return nil
	}
	// pfctl accepts mismatched prefix lengths (M0 T10c); we do not.
	if n.Address == nil || len(r.From.Prefixes) != 1 {
		return invalid("binat-to: needs exactly one source prefix and a target address")
	}
	if r.From.Prefixes[0].Bits() != n.Address.Bits() {
		return invalid("binat-to: prefix lengths differ (%d vs %d)", r.From.Prefixes[0].Bits(), n.Address.Bits())
	}
	return nil
}

func (n NAT) validateAFTo(r Rule) error {
	if r.Action != Pass || r.Direction != In {
		return invalid("af-to: only on pass in rules")
	}
	if n.ToFamily != Inet && n.ToFamily != Inet6 {
		return invalid("af-to: to_family must be inet or inet6")
	}
	if n.ToFamily == r.Family {
		return invalid("af-to: to_family must differ from the rule family")
	}
	if n.AFFrom == nil {
		return invalid("af-to: af_from is required")
	}
	if err := checkPrefix(*n.AFFrom, n.ToFamily, "af_from"); err != nil {
		return err
	}
	if n.AFTo != nil {
		if err := checkPrefix(*n.AFTo, n.ToFamily, "af_to"); err != nil {
			return err
		}
	}
	if n.Address != nil || n.Interface != "" || n.Port != nil {
		return invalid("af-to: use af_from/af_to, not address/interface/port")
	}
	return nil
}

// Validate checks a single rule against the policy.
func (r Rule) Validate(pol Policy) error {
	if err := r.validateHeader(pol); err != nil {
		return err
	}
	if r.BlockReturn && r.Action != Block {
		return invalid("block_return only applies to block")
	}
	if r.Quick && r.Action == Match {
		return invalid("match rules cannot be quick")
	}
	if err := r.From.validate("from", r.Family, r.Protocol, pol); err != nil {
		return err
	}
	if err := r.To.validate("to", r.Family, r.Protocol, pol); err != nil {
		return err
	}
	if err := r.validateNAT(pol); err != nil {
		return err
	}
	if err := r.validatePrio(); err != nil {
		return err
	}
	if r.Queue != nil {
		return invalid("queue: set queue is only allowed in the QoS document (/v1/qos); use prio here")
	}
	if !labelRe.MatchString(r.Label) {
		return invalid("label may only contain letters, digits, space and _.:/- (max 63)")
	}
	return nil
}

// validateHeader checks action, direction, interface, family and protocol.
func (r Rule) validateHeader(pol Policy) error {
	switch r.Action {
	case Pass, Block, Match:
	default:
		return invalid("action %q", r.Action)
	}
	switch r.Direction {
	case In, Out, Both:
	default:
		return invalid("direction %q", r.Direction)
	}
	if r.Interface == "" || !contains(pol.Interfaces, r.Interface) {
		return invalid("interface %q is not allowed", r.Interface)
	}
	if r.Family != Inet && r.Family != Inet6 {
		return invalid("family must be inet or inet6")
	}
	return r.validateProtocol()
}

func (r Rule) validateProtocol() error {
	switch r.Protocol {
	case AnyProto, TCP, UDP:
	case ICMP:
		if r.Family != Inet {
			return invalid("icmp needs family inet (use icmp6)")
		}
	case ICMP6:
		if r.Family != Inet6 {
			return invalid("icmp6 needs family inet6")
		}
	default:
		return invalid("protocol %q", r.Protocol)
	}
	return nil
}

func (r Rule) validateNAT(pol Policy) error {
	if r.NAT == nil {
		return nil
	}
	if r.Action == Block {
		return invalid("nat on a block rule")
	}
	return r.NAT.validate(r, pol)
}

func (r Rule) validatePrio() error {
	if r.Prio == nil {
		return nil
	}
	if r.Prio.Normal > 7 || (r.Prio.Low != nil && *r.Prio.Low > 7) {
		return invalid("prio must be 0..7")
	}
	if r.Action == Block {
		return invalid("prio on a block rule")
	}
	return nil
}

// Validate checks an anchor and every rule in it.
func (a Anchor) Validate(pol Policy) error {
	if !ValidName(a.Name) {
		return invalid("anchor name %q", a.Name)
	}
	limit := pol.MaxRules
	if limit <= 0 {
		limit = 1000
	}
	if len(a.Rules) > limit {
		return invalid("%d rules exceeds the limit of %d", len(a.Rules), limit)
	}
	for i, r := range a.Rules {
		if err := r.Validate(pol); err != nil {
			return fmt.Errorf("rule %d: %w", i, err)
		}
	}
	return nil
}

// Validate checks a table's name and entries. Entries may mix families.
func (t Table) Validate(pol Policy) error {
	if !ValidName(t.Name) || !contains(pol.Tables, t.Name) {
		return invalid("table %q is not a managed table", t.Name)
	}
	limit := pol.MaxTableEntries
	if limit <= 0 {
		limit = 65536
	}
	if len(t.Entries) > limit {
		return invalid("%d entries exceeds the limit of %d", len(t.Entries), limit)
	}
	seen := make(map[netip.Prefix]bool, len(t.Entries))
	for _, p := range t.Entries {
		if err := checkPrefix(p, familyOf(p), "entry"); err != nil {
			return err
		}
		if seen[p] {
			return invalid("duplicate entry %s", p)
		}
		seen[p] = true
	}
	return nil
}

// Validate checks the policy itself (loaded from the root-owned config).
func (p Policy) Validate() error {
	errs := interfaceErrs("interface", p.Interfaces)
	errs = append(errs, interfaceErrs("queue interface", p.QueueInterfaces)...)
	for _, n := range p.Tables {
		if !ValidName(n) {
			errs = append(errs, fmt.Sprintf("table %q", n))
		}
	}
	for _, n := range p.InternalNets {
		if !n.IsValid() || n != n.Masked() {
			errs = append(errs, fmt.Sprintf("internal net %s", n))
		}
	}
	if len(errs) > 0 {
		return invalid("policy: %s", strings.Join(errs, "; "))
	}
	return nil
}

// interfaceErrs checks a list of interface (group) names; mgmt is never
// allowed.
func interfaceErrs(what string, names []string) []string {
	var errs []string
	for _, n := range names {
		if !ValidName(n) {
			errs = append(errs, fmt.Sprintf("%s %q", what, n))
		}
		if n == "mgmt" {
			errs = append(errs, "the mgmt group is read-only and may not be listed")
		}
	}
	return errs
}

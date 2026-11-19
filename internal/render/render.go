// Package render turns validated model objects into pf.conf text.
//
// Output is deterministic (no timestamps, fixed ordering) so a file's hash
// identifies its content. Every rule is one line. Callers must Validate the
// object first; Anchor still runs Guard on its own output as defence in
// depth, because pfctl itself accepts `include` and nested anchors inside an
// anchor file (M0 T7c/T7d).
package render

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/pderuiter/pfapid/internal/model"
)

const header = "# Managed by pfapid. Do not edit: changes are overwritten and show up as drift.\n"

// ErrGuard means rendered output failed the structural check. It always
// indicates a bug (validation let something through), never user error.
var ErrGuard = errors.New("render guard")

func ports(prs []model.PortRange) string {
	one := func(p model.PortRange) string {
		if p.To == 0 {
			return strconv.Itoa(int(p.From))
		}
		return strconv.Itoa(int(p.From)) + ":" + strconv.Itoa(int(p.To))
	}
	if len(prs) == 1 {
		return " port " + one(prs[0])
	}
	parts := make([]string, len(prs))
	for i, p := range prs {
		parts[i] = one(p)
	}
	return " port { " + strings.Join(parts, " ") + " }"
}

func endpoint(e model.Endpoint) string {
	var s string
	switch {
	case len(e.Prefixes) == 1:
		s = e.Prefixes[0].String()
	case len(e.Prefixes) > 1:
		parts := make([]string, len(e.Prefixes))
		for i, p := range e.Prefixes {
			parts[i] = p.String()
		}
		s = "{ " + strings.Join(parts, " ") + " }"
	case e.Table != "":
		s = "<" + e.Table + ">"
	case e.Interface != "":
		s = "(" + e.Interface + ")"
	default:
		s = "any"
	}
	if len(e.Ports) > 0 {
		s += ports(e.Ports)
	}
	return s
}

func nat(n model.NAT) string {
	var b strings.Builder
	b.WriteString(" ")
	b.WriteString(string(n.Kind))
	if n.Kind == model.AFTo {
		b.WriteString(" " + string(n.ToFamily) + " from " + n.AFFrom.String())
		if n.AFTo != nil {
			b.WriteString(" to " + n.AFTo.String())
		}
		return b.String()
	}
	if n.Address != nil {
		b.WriteString(" " + n.Address.String())
	} else {
		b.WriteString(" (" + n.Interface + ":0)")
	}
	if n.Port != nil {
		b.WriteString(" port " + strconv.Itoa(int(n.Port.From)))
		if n.Port.To != 0 {
			b.WriteString(":" + strconv.Itoa(int(n.Port.To)))
		}
	}
	return b.String()
}

// Rule renders one validated rule as a single line (no newline).
func Rule(r model.Rule) string {
	var b strings.Builder
	b.WriteString(string(r.Action))
	if r.BlockReturn {
		b.WriteString(" return")
	}
	if r.Direction != model.Both {
		b.WriteString(" " + string(r.Direction))
	}
	if r.Log {
		b.WriteString(" log")
	}
	if r.Quick {
		b.WriteString(" quick")
	}
	b.WriteString(" on " + r.Interface)
	b.WriteString(" " + string(r.Family))
	if r.Protocol != model.AnyProto {
		b.WriteString(" proto " + string(r.Protocol))
	}
	b.WriteString(" from " + endpoint(r.From))
	b.WriteString(" to " + endpoint(r.To))
	if r.NAT != nil {
		b.WriteString(nat(*r.NAT))
	}
	if r.Prio != nil {
		if r.Prio.Low != nil {
			fmt.Fprintf(&b, " set prio (%d, %d)", r.Prio.Normal, *r.Prio.Low)
		} else {
			fmt.Fprintf(&b, " set prio %d", r.Prio.Normal)
		}
	}
	if r.Queue != nil {
		if r.Queue.Priority != "" {
			fmt.Fprintf(&b, " set queue (%s, %s)", r.Queue.Name, r.Queue.Priority)
		} else {
			b.WriteString(" set queue " + r.Queue.Name)
		}
	}
	if r.Label != "" {
		b.WriteString(` label "` + r.Label + `"`)
	}
	return b.String()
}

// Anchor renders the file loaded into api/<name>. It returns ErrGuard if the
// output is not exactly one header plus one allowed line per rule.
func Anchor(a model.Anchor) ([]byte, error) {
	var b strings.Builder
	b.WriteString(header)
	for _, r := range a.Rules {
		b.WriteString(Rule(r))
		b.WriteString("\n")
	}
	out := []byte(b.String())
	if err := Guard(out, len(a.Rules)); err != nil {
		return nil, err
	}
	return out, nil
}

// Guard checks rendered anchor text structurally: the managed header, then
// exactly n lines, each starting with pass/block/match, and none containing
// a token that changes what gets loaded (include, anchor, load, table, queue,
// macros) or a control character.
func Guard(text []byte, n int) error { return guard(text, n, false) }

// guard is Guard; with qos set, every line must be a match rule and the word
// queue may appear, but only as `set queue`.
func guard(text []byte, n int, qos bool) error {
	s := string(text)
	if !strings.HasPrefix(s, header) {
		return fmt.Errorf("%w: missing header", ErrGuard)
	}
	body := strings.TrimSuffix(strings.TrimPrefix(s, header), "\n")
	var lines []string
	if body != "" {
		lines = strings.Split(body, "\n")
	}
	if len(lines) != n {
		return fmt.Errorf("%w: %d lines for %d rules", ErrGuard, len(lines), n)
	}
	for i, l := range lines {
		if err := guardLine(i, l, qos); err != nil {
			return err
		}
	}
	return nil
}

// guardLine checks one rendered rule line.
func guardLine(i int, l string, qos bool) error {
	for _, c := range l {
		if c < 0x20 || c == 0x7f || c == '\\' {
			return fmt.Errorf("%w: line %d: control or escape character", ErrGuard, i)
		}
	}
	code, err := lineCode(i, l)
	if err != nil {
		return err
	}
	f := strings.Fields(code)
	if len(f) == 0 {
		return fmt.Errorf("%w: line %d empty", ErrGuard, i)
	}
	switch {
	case f[0] == "match", !qos && (f[0] == "pass" || f[0] == "block"):
	default:
		return fmt.Errorf("%w: line %d starts with %q", ErrGuard, i, f[0])
	}
	return guardWords(i, f, qos)
}

// lineCode is the line without its trailing label. The only quoted string
// allowed is a trailing label; keywords are checked outside it so a label
// may say anything labelRe allows.
func lineCode(i int, l string) (string, error) {
	q := strings.Index(l, `"`)
	if q < 0 {
		return l, nil
	}
	if !strings.HasSuffix(l[:q], " label ") || !strings.HasSuffix(l, `"`) || strings.Count(l, `"`) != 2 {
		return "", fmt.Errorf("%w: line %d: quote outside a trailing label", ErrGuard, i)
	}
	return l[:q], nil
}

// guardWords rejects tokens that change what gets loaded; in QoS only
// `set queue` is allowed.
func guardWords(i int, f []string, qos bool) error {
	for j, w := range f {
		if qos && w == "queue" && j > 0 && f[j-1] == "set" {
			continue
		}
		switch w {
		case "include", "anchor", "load", "table", "queue", "set-queue", "=":
			return fmt.Errorf("%w: line %d contains %q", ErrGuard, i, w)
		}
	}
	return nil
}

// TableEntries renders the input for `pfctl -t <name> -T replace -f`.
func TableEntries(t model.Table) []byte {
	var b strings.Builder
	for _, p := range t.Entries {
		b.WriteString(p.String())
		b.WriteString("\n")
	}
	return []byte(b.String())
}

// IncludeFile renders the generated file the base ruleset includes, so that
// API anchors are loaded at boot. names must be validated anchor names.
func IncludeFile(dir string, names []string) []byte {
	var b strings.Builder
	b.WriteString(header)
	for _, n := range names {
		fmt.Fprintf(&b, "load anchor \"api/%s\" from \"%s/%s.conf\"\n", n, dir, n)
	}
	return []byte(b.String())
}

// QoSAnchor is the QoSRules file loaded into the api-qos anchor by the base
// ruleset (`load anchor "api-qos" from ...`): match rules only.
func QoSAnchor(q model.QoS) ([]byte, error) {
	var b strings.Builder
	b.WriteString(header)
	for _, r := range q.Rules {
		b.WriteString(Rule(r))
		b.WriteString("\n")
	}
	out := []byte(b.String())
	if err := guard(out, len(q.Rules), true); err != nil {
		return nil, err
	}
	return out, nil
}

// Queue renders one validated queue definition as a single line.
func Queue(q model.Queue) string {
	var b strings.Builder
	b.WriteString("queue " + q.Name)
	if q.Interface != "" {
		b.WriteString(" on " + q.Interface)
	} else {
		b.WriteString(" parent " + q.Parent)
	}
	b.WriteString(" bandwidth " + q.Bandwidth)
	if q.Min != "" {
		b.WriteString(" min " + q.Min)
	}
	if q.Max != "" {
		b.WriteString(" max " + q.Max)
	}
	if q.Flows > 0 {
		fmt.Fprintf(&b, " flows %d", q.Flows)
	}
	if q.Quantum > 0 {
		fmt.Fprintf(&b, " quantum %d", q.Quantum)
	}
	if q.QLimit > 0 {
		fmt.Fprintf(&b, " qlimit %d", q.QLimit)
	}
	if q.Default {
		b.WriteString(" default")
	}
	return b.String()
}

var queueKeyword = map[string]bool{
	"queue": true, "on": true, "parent": true, "bandwidth": true, "min": true,
	"max": true, "flows": true, "quantum": true, "qlimit": true, "default": true,
}

// QueueFile renders the file the base ruleset includes in its main section
// (`include ".../api-queues.conf"`). Every line is checked: it is a queue
// definition made of known keywords, names and numbers only, because this
// file is parsed as part of the main ruleset.
func QueueFile(q model.QoS) ([]byte, error) {
	var b strings.Builder
	b.WriteString(header)
	for _, qu := range q.Queues {
		b.WriteString(Queue(qu))
		b.WriteString("\n")
	}
	out := []byte(b.String())
	body := strings.TrimSuffix(strings.TrimPrefix(string(out), header), "\n")
	var lines []string
	if body != "" {
		lines = strings.Split(body, "\n")
	}
	if len(lines) != len(q.Queues) {
		return nil, fmt.Errorf("%w: %d lines for %d queues", ErrGuard, len(lines), len(q.Queues))
	}
	for i, l := range lines {
		f := strings.Fields(l)
		if len(f) < 4 || f[0] != "queue" {
			return nil, fmt.Errorf("%w: queue line %d malformed", ErrGuard, i)
		}
		for _, w := range f {
			if !queueKeyword[w] && !model.ValidName(w) && !queueValue.MatchString(w) {
				return nil, fmt.Errorf("%w: queue line %d: unexpected token %q", ErrGuard, i, w)
			}
		}
	}
	return out, nil
}

var queueValue = regexp.MustCompile(`^[0-9]{1,12}[KMG]?$`)

package model

import (
	"fmt"
	"regexp"
	"strconv"
)

// QoS is the single QoS document of a firewall: the HFSC queue trees and the
// classification rules that assign traffic to them.
//
// It is its own domain (M0 T1/T1b): pf only accepts queue definitions in the
// main ruleset, and an anchor rule can only `set queue` when the anchor is
// loaded as part of a main load. QoS is therefore applied with a full reload
// of the base ruleset, which includes the API's queue file and loads the
// api-qos anchor. Normal anchors may use `set prio` but never `set queue`.
type QoS struct {
	Queues []Queue `json:"queues"`
	// Rules classify only: every rule is a `match` rule (no pass, block or
	// NAT), so the QoS domain can never change what the firewall permits.
	Rules []Rule `json:"rules"`
}

// Queue is one HFSC queue. A root queue names a physical interface; every
// other queue names its parent. Bandwidths are pf bit rates: a number with
// an optional K, M or G suffix (pf has no percentages, M0 T1e).
type Queue struct {
	Name      string `json:"name"`
	Interface string `json:"interface,omitempty"` // root queues only
	Parent    string `json:"parent,omitempty"`    // every other queue
	Bandwidth string `json:"bandwidth"`
	Min       string `json:"min,omitempty"`
	Max       string `json:"max,omitempty"`
	QLimit    int    `json:"qlimit,omitempty"`
	Default   bool   `json:"default,omitempty"`
	// Flows turns the queue into an FQ-CoDel queue with that many flows;
	// Quantum (bytes) only applies to such a queue.
	Flows   int `json:"flows,omitempty"`
	Quantum int `json:"quantum,omitempty"`
}

// QueueSet is `set queue name` or `set queue (name, priority)`: the second
// queue takes low-delay and TCP ACK packets.
type QueueSet struct {
	Name     string `json:"name"`
	Priority string `json:"priority,omitempty"`
}

var bandwidthRe = regexp.MustCompile(`^([1-9][0-9]{0,11})([KMG]?)$`)

// BitRate parses a pf bandwidth ("100M") into bits per second.
func BitRate(s string) (uint64, error) {
	m := bandwidthRe.FindStringSubmatch(s)
	if m == nil {
		return 0, invalid("bandwidth %q: use a number with an optional K, M or G suffix, e.g. 100M", s)
	}
	n, _ := strconv.ParseUint(m[1], 10, 64) // regexp guarantees a small decimal
	mult := map[string]uint64{"": 1, "K": 1e3, "M": 1e6, "G": 1e9}[m[2]]
	return n * mult, nil
}

const (
	maxQueues = 256
	maxFlows  = 32767
)

// Validate checks the queue trees and the classification rules.
func (q QoS) Validate(pol Policy) error {
	if len(q.Queues) > maxQueues {
		return invalid("%d queues exceeds the limit of %d", len(q.Queues), maxQueues)
	}
	if len(q.Queues) > 0 && len(pol.QueueInterfaces) == 0 {
		return invalid("QoS is not enabled on this firewall (policy.queue_interfaces is empty)")
	}
	qc := newQueueCheck(pol)
	for i := range q.Queues {
		if err := qc.add(i, &q.Queues[i]); err != nil {
			return err
		}
	}
	if err := qc.checkDefaults(q.Queues); err != nil {
		return err
	}

	limit := pol.MaxRules
	if limit <= 0 {
		limit = 1000
	}
	if len(q.Rules) > limit {
		return invalid("%d rules exceeds the limit of %d", len(q.Rules), limit)
	}
	for i, r := range q.Rules {
		if err := r.validateQoS(pol, qc.byName); err != nil {
			return fmt.Errorf("rule %d: %w", i, err)
		}
	}
	return nil
}

// queueCheck accumulates what Validate needs to know about the queues
// defined so far (a parent must be defined before its children).
type queueCheck struct {
	pol      Policy
	byName   map[string]*Queue
	rate     map[string]uint64
	children map[string]uint64 // sum of child bandwidths per parent
	hasChild map[string]bool
	rootOf   map[string]string
	rootIf   map[string]bool
}

func newQueueCheck(pol Policy) *queueCheck {
	return &queueCheck{
		pol:      pol,
		byName:   map[string]*Queue{},
		rate:     map[string]uint64{},
		children: map[string]uint64{},
		hasChild: map[string]bool{},
		rootOf:   map[string]string{},
		rootIf:   map[string]bool{},
	}
}

func (qc *queueCheck) add(i int, qu *Queue) error {
	what := fmt.Sprintf("queue %d (%s)", i, qu.Name)
	if !ValidName(qu.Name) {
		return invalid("queue %d: name %q", i, qu.Name)
	}
	if qc.byName[qu.Name] != nil {
		return invalid("%s: duplicate name", what)
	}
	bw, err := BitRate(qu.Bandwidth)
	if err != nil {
		return fmt.Errorf("%s: %w", what, err)
	}
	if err := qc.place(what, qu, bw); err != nil {
		return err
	}
	if err := checkMinMax(what, qu, bw); err != nil {
		return err
	}
	if err := checkQueueSizes(what, qu); err != nil {
		return err
	}
	qc.byName[qu.Name] = qu
	qc.rate[qu.Name] = bw
	return nil
}

// place checks where the queue sits: a root on an interface, or a child of
// an already defined parent.
func (qc *queueCheck) place(what string, qu *Queue, bw uint64) error {
	switch {
	case qu.Interface != "" && qu.Parent != "":
		return invalid("%s: set interface (root queue) or parent, not both", what)
	case qu.Interface != "":
		return qc.placeRoot(what, qu)
	case qu.Parent != "":
		return qc.placeChild(what, qu, bw)
	default:
		return invalid("%s: set interface (root queue) or parent", what)
	}
}

func (qc *queueCheck) placeRoot(what string, qu *Queue) error {
	if !contains(qc.pol.QueueInterfaces, qu.Interface) {
		return invalid("%s: interface %q is not in policy.queue_interfaces", what, qu.Interface)
	}
	if qc.rootIf[qu.Interface] {
		return invalid("%s: interface %s already has a root queue", what, qu.Interface)
	}
	qc.rootIf[qu.Interface] = true
	qc.rootOf[qu.Name] = qu.Name
	if qu.Default {
		return invalid("%s: a root queue cannot be the default queue", what)
	}
	return nil
}

func (qc *queueCheck) placeChild(what string, qu *Queue, bw uint64) error {
	p := qc.byName[qu.Parent]
	if p == nil {
		return invalid("%s: parent %q must be defined before it", what, qu.Parent)
	}
	if p.Flows > 0 {
		return invalid("%s: parent %q is a flow queue and cannot have children", what, p.Name)
	}
	qc.children[qu.Parent] += bw
	if qc.children[qu.Parent] > qc.rate[qu.Parent] {
		// pfctl accepts an oversubscribed parent (M0 T1f); we do not.
		return invalid("%s: children of %q add up to more than its bandwidth %s", what, qu.Parent, p.Bandwidth)
	}
	qc.hasChild[qu.Parent] = true
	qc.rootOf[qu.Name] = qc.rootOf[qu.Parent]
	return nil
}

func checkMinMax(what string, qu *Queue, bw uint64) error {
	if qu.Min != "" {
		mn, err := BitRate(qu.Min)
		if err != nil {
			return fmt.Errorf("%s: min: %w", what, err)
		}
		if mn > bw {
			return invalid("%s: min is above bandwidth", what)
		}
	}
	if qu.Max != "" {
		mx, err := BitRate(qu.Max)
		if err != nil {
			return fmt.Errorf("%s: max: %w", what, err)
		}
		if mx < bw {
			return invalid("%s: max is below bandwidth", what)
		}
	}
	return nil
}

func checkQueueSizes(what string, qu *Queue) error {
	if qu.QLimit < 0 || qu.QLimit > 65535 {
		return invalid("%s: qlimit must be 1..65535", what)
	}
	if qu.Flows < 0 || qu.Flows > maxFlows {
		return invalid("%s: flows must be 1..%d", what, maxFlows)
	}
	if qu.Quantum < 0 || qu.Quantum > 65535 {
		return invalid("%s: quantum must be 1..65535", what)
	}
	if qu.Quantum > 0 && qu.Flows == 0 {
		return invalid("%s: quantum only applies to a flow queue (set flows)", what)
	}
	return nil
}

// checkDefaults: exactly one default per tree, and it must be a leaf (pfctl:
// "no default queue specified" otherwise).
func (qc *queueCheck) checkDefaults(queues []Queue) error {
	defaults := map[string]int{}
	for _, qu := range queues {
		if !qu.Default {
			continue
		}
		if qc.hasChild[qu.Name] {
			return invalid("queue %s: the default queue must be a leaf", qu.Name)
		}
		defaults[qc.rootOf[qu.Name]]++
	}
	for _, qu := range queues {
		if qu.Interface != "" && defaults[qu.Name] != 1 {
			return invalid("queue tree %s (%s) needs exactly one default queue, has %d", qu.Name, qu.Interface, defaults[qu.Name])
		}
	}
	return nil
}

func (r Rule) validateQoS(pol Policy, queues map[string]*Queue) error {
	if r.Action != Match {
		return invalid("QoS rules classify only: action must be match")
	}
	if r.NAT != nil {
		return invalid("QoS rules cannot translate (nat)")
	}
	if r.Queue == nil && r.Prio == nil {
		return invalid("a QoS rule needs queue or prio")
	}
	if r.Queue != nil {
		if err := r.Queue.validateRefs(queues); err != nil {
			return err
		}
	}
	rr := r
	rr.Queue = nil // the generic checks reject Queue outside QoS
	return rr.Validate(pol)
}

// validateRefs checks that both queues of `set queue` exist and are leaves.
func (qs QueueSet) validateRefs(queues map[string]*Queue) error {
	for _, n := range []string{qs.Name, qs.Priority} {
		if n == "" {
			continue
		}
		if queues[n] == nil {
			return invalid("queue %q is not defined", n)
		}
		if hasChildren(queues, n) {
			return invalid("queue %q has children; rules must assign leaf queues", n)
		}
	}
	if qs.Name == "" {
		return invalid("queue.name is required")
	}
	return nil
}

func hasChildren(queues map[string]*Queue, name string) bool {
	for _, other := range queues {
		if other.Parent == name {
			return true
		}
	}
	return false
}

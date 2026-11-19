package model

import (
	"strings"
	"testing"
)

var qpol = Policy{Interfaces: []string{"frontend"}, QueueInterfaces: []string{"vio1", "vio2"}}

func tree() []Queue {
	return []Queue{
		{Name: "rootq", Interface: "vio1", Bandwidth: "100M"},
		{Name: "std", Parent: "rootq", Bandwidth: "60M", Default: true},
		{Name: "bulk", Parent: "rootq", Bandwidth: "20M", Max: "30M", QLimit: 100},
		{Name: "fq", Parent: "rootq", Bandwidth: "20M", Flows: 1024, Quantum: 1500},
	}
}

func classify(q *QueueSet) Rule {
	return Rule{Action: Match, Direction: Out, Interface: "frontend", Family: Inet, Queue: q}
}

func TestQoSValid(t *testing.T) {
	q := QoS{Queues: tree(), Rules: []Rule{classify(&QueueSet{Name: "bulk", Priority: "std"})}}
	if err := q.Validate(qpol); err != nil {
		t.Fatal(err)
	}
	if err := (QoS{}).Validate(Policy{}); err != nil {
		t.Fatalf("empty QoS without queue interfaces: %v", err)
	}
}

func TestQoSInvalid(t *testing.T) {
	mod := func(f func(q *QoS)) QoS {
		q := QoS{Queues: tree()}
		f(&q)
		return q
	}
	for want, q := range map[string]QoS{
		"bandwidth":              mod(func(q *QoS) { q.Queues[1].Bandwidth = "50%" }),
		"not in policy":          mod(func(q *QoS) { q.Queues[0].Interface = "frontend" }),
		"already has a root":     mod(func(q *QoS) { q.Queues = append(q.Queues, Queue{Name: "r2", Interface: "vio1", Bandwidth: "1M"}) }),
		"defined before":         mod(func(q *QoS) { q.Queues[1].Parent = "nope" }),
		"add up to more":         mod(func(q *QoS) { q.Queues[2].Bandwidth = "25M" }),
		"exactly one default":    mod(func(q *QoS) { q.Queues[1].Default = false }),
		"root queue cannot":      mod(func(q *QoS) { q.Queues[0].Default = true }),
		"duplicate":              mod(func(q *QoS) { q.Queues[2].Name = "std" }),
		"quantum only":           mod(func(q *QoS) { q.Queues[2].Quantum = 100 }),
		"max is below":           mod(func(q *QoS) { q.Queues[2].Max = "10M" }),
		"interface (root queue)": mod(func(q *QoS) { q.Queues[1].Interface = "vio2" }),
		"flow queue":             mod(func(q *QoS) { q.Queues = append(q.Queues, Queue{Name: "sub", Parent: "fq", Bandwidth: "1M"}) }),
		"action must be match":   mod(func(q *QoS) { r := classify(&QueueSet{Name: "bulk"}); r.Action = Pass; q.Rules = []Rule{r} }),
		"is not defined":         mod(func(q *QoS) { q.Rules = []Rule{classify(&QueueSet{Name: "x"})} }),
		"leaf queues":            mod(func(q *QoS) { q.Rules = []Rule{classify(&QueueSet{Name: "rootq"})} }),
		"needs queue or prio":    mod(func(q *QoS) { q.Rules = []Rule{classify(nil)} }),
		"cannot translate": mod(func(q *QoS) {
			r := classify(&QueueSet{Name: "bulk"})
			r.NAT = &NAT{Kind: NATTo, Interface: "frontend"}
			q.Rules = []Rule{r}
		}),
	} {
		err := q.Validate(qpol)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: got %v", want, err)
		}
	}
	if err := (QoS{Queues: tree()}).Validate(Policy{}); err == nil {
		t.Error("queues accepted without queue_interfaces")
	}
}

func TestSetQueueOnlyInQoS(t *testing.T) {
	a := Anchor{Name: "k8s", Rules: []Rule{classify(&QueueSet{Name: "bulk"})}}
	if err := a.Validate(qpol); err == nil || !strings.Contains(err.Error(), "only allowed in the QoS") {
		t.Fatalf("set queue in a normal anchor: %v", err)
	}
}

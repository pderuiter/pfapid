package ipc

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/pderuiter/pfapid/internal/model"
	"github.com/pderuiter/pfapid/internal/priv"
)

type stub struct{ priv.Backend }

func (stub) GetAnchor(_ context.Context, name string) (priv.AnchorState, error) {
	if name == "missing" {
		return priv.AnchorState{}, &priv.Error{Code: priv.CodeNotFound, Msg: "nope"}
	}
	return priv.AnchorState{Anchor: model.Anchor{Name: name}, ETag: "e1"}, nil
}
func (stub) Pending(context.Context) (*priv.ChangeInfo, error) { return nil, nil }

func TestRoundTrip(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	go func() { _ = Serve(context.Background(), b, stub{}, nil) }()
	c := NewClient(a)
	st, err := c.GetAnchor(context.Background(), "k8s")
	if err != nil || st.ETag != "e1" || st.Anchor.Name != "k8s" {
		t.Fatalf("%+v %v", st, err)
	}
	_, err = c.GetAnchor(context.Background(), "missing")
	var pe *priv.Error
	if !errors.As(err, &pe) || pe.Code != priv.CodeNotFound {
		t.Fatalf("error code lost over ipc: %v", err)
	}
	if p, err := c.Pending(context.Background()); p != nil || err != nil {
		t.Fatalf("pending: %v %v", p, err)
	}
}

func TestOversizedMessageRefused(t *testing.T) {
	a, b := net.Pipe()
	defer a.Close()
	go func() { _, _ = a.Write([]byte{0x7f, 0xff, 0xff, 0xff}) }()
	var v any
	if err := readMsg(b, &v); err == nil {
		t.Fatal("oversized length accepted")
	}
}

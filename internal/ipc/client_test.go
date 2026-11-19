package ipc

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/pderuiter/pfapid/internal/api"
	"github.com/pderuiter/pfapid/internal/model"
	"github.com/pderuiter/pfapid/internal/priv"
)

// full records every call with its arguments and echoes them back.
type full struct{ calls []string }

func (f *full) rec(s string) { f.calls = append(f.calls, s) }

func (f *full) ListAnchors(context.Context) ([]string, error) {
	f.rec("ListAnchors")
	return []string{"a", "b"}, nil
}
func (f *full) GetAnchor(_ context.Context, n string) (priv.AnchorState, error) {
	f.rec("GetAnchor " + n)
	return priv.AnchorState{Anchor: model.Anchor{Name: n}, ETag: "e"}, nil
}
func (f *full) PutAnchor(_ context.Context, actor string, a model.Anchor, pre priv.Precondition) (priv.ChangeInfo, error) {
	f.rec("PutAnchor " + actor + " " + a.Name + " " + pre.IfMatch)
	return priv.ChangeInfo{ID: "1", Name: a.Name}, nil
}
func (f *full) DeleteAnchor(_ context.Context, actor, n string, pre priv.Precondition) (priv.ChangeInfo, error) {
	f.rec("DeleteAnchor " + actor + " " + n + " " + pre.IfMatch)
	return priv.ChangeInfo{ID: "2", Name: n, Op: "delete"}, nil
}
func (f *full) ValidateAnchor(_ context.Context, a model.Anchor) (priv.ValidateResult, error) {
	f.rec("ValidateAnchor " + a.Name)
	return priv.ValidateResult{Rendered: []string{"r"}}, nil
}
func (f *full) DriftAnchor(_ context.Context, n string) (priv.DriftResult, error) {
	f.rec("DriftAnchor " + n)
	return priv.DriftResult{InSync: true}, nil
}
func (f *full) ListTables(context.Context) ([]string, error) {
	f.rec("ListTables")
	return []string{"t"}, nil
}
func (f *full) GetTable(_ context.Context, n string) (priv.TableState, error) {
	f.rec("GetTable " + n)
	return priv.TableState{Table: model.Table{Name: n}, ETag: "te"}, nil
}
func (f *full) PutTable(_ context.Context, actor string, t model.Table, pre priv.Precondition) (priv.ChangeInfo, error) {
	f.rec("PutTable " + actor + " " + t.Name + " " + t.Entries[0].String())
	return priv.ChangeInfo{ID: "3", Name: t.Name}, nil
}
func (f *full) DriftTable(_ context.Context, n string) (priv.DriftResult, error) {
	f.rec("DriftTable " + n)
	return priv.DriftResult{Live: []string{"x"}}, nil
}
func (f *full) GetQoS(context.Context) (priv.QoSState, error) {
	f.rec("GetQoS")
	return priv.QoSState{ETag: "q"}, nil
}
func (f *full) PutQoS(_ context.Context, actor string, q model.QoS, pre priv.Precondition) (priv.ChangeInfo, error) {
	f.rec("PutQoS " + actor + " " + q.Queues[0].Name)
	return priv.ChangeInfo{ID: "4"}, nil
}
func (f *full) ValidateQoS(_ context.Context, q model.QoS) (priv.ValidateResult, error) {
	f.rec("ValidateQoS " + q.Queues[0].Name)
	return priv.ValidateResult{Normalised: []string{"n"}}, nil
}
func (f *full) DriftQoS(context.Context) (priv.DriftResult, error) {
	f.rec("DriftQoS")
	return priv.DriftResult{InSync: true}, nil
}
func (f *full) Pending(context.Context) (*priv.ChangeInfo, error) {
	f.rec("Pending")
	return &priv.ChangeInfo{ID: "5"}, nil
}
func (f *full) Confirm(_ context.Context, actor, id string, admin bool) error {
	f.rec("Confirm " + actor + " " + id)
	if !admin {
		return &priv.Error{Code: priv.CodeForbidden, Msg: "not yours"}
	}
	return nil
}
func (f *full) Rollback(_ context.Context, actor, id string, _ bool) error {
	f.rec("Rollback " + actor + " " + id)
	return nil
}

func serve(t *testing.T, b priv.Backend, src TLSSource) *Client {
	t.Helper()
	a, s := net.Pipe()
	t.Cleanup(func() { _ = a.Close() })
	go func() { _ = Serve(context.Background(), s, b, src) }()
	return NewClient(a)
}

// Every Backend method travels over the socket with its arguments and result.
func TestEveryOp(t *testing.T) {
	f := &full{}
	c := serve(t, f, nil)
	ctx := context.Background()
	pre := priv.Precondition{IfMatch: "m"}
	q := model.QoS{Queues: []model.Queue{{Name: "root"}}}
	check := func(what string, ok bool, err error) {
		t.Helper()
		if err != nil || !ok {
			t.Fatalf("%s: ok=%v err=%v", what, ok, err)
		}
	}
	l, err := c.ListAnchors(ctx)
	check("ListAnchors", len(l) == 2, err)
	ci, err := c.PutAnchor(ctx, "tf", model.Anchor{Name: "k8s"}, pre)
	check("PutAnchor", ci.ID == "1" && ci.Name == "k8s", err)
	ci, err = c.DeleteAnchor(ctx, "tf", "k8s", pre)
	check("DeleteAnchor", ci.Op == "delete", err)
	vr, err := c.ValidateAnchor(ctx, model.Anchor{Name: "k8s"})
	check("ValidateAnchor", len(vr.Rendered) == 1, err)
	dr, err := c.DriftAnchor(ctx, "k8s")
	check("DriftAnchor", dr.InSync, err)
	l, err = c.ListTables(ctx)
	check("ListTables", len(l) == 1, err)
	ts, err := c.GetTable(ctx, "t")
	check("GetTable", ts.ETag == "te", err)
	ci, err = c.PutTable(ctx, "tf", model.Table{Name: "t", Entries: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}, pre)
	check("PutTable", ci.ID == "3", err)
	dr, err = c.DriftTable(ctx, "t")
	check("DriftTable", len(dr.Live) == 1, err)
	qs, err := c.GetQoS(ctx)
	check("GetQoS", qs.ETag == "q", err)
	ci, err = c.PutQoS(ctx, "netops", q, pre)
	check("PutQoS", ci.ID == "4", err)
	vr, err = c.ValidateQoS(ctx, q)
	check("ValidateQoS", len(vr.Normalised) == 1, err)
	dr, err = c.DriftQoS(ctx)
	check("DriftQoS", dr.InSync, err)
	p, err := c.Pending(ctx)
	check("Pending", p != nil && p.ID == "5", err)
	check("Confirm", true, c.Confirm(ctx, "admin", "abc", true))
	check("Rollback", true, c.Rollback(ctx, "tf", "abc", false))

	var pe *priv.Error
	if err := c.Confirm(ctx, "tf", "abc", false); !errors.As(err, &pe) || pe.Code != priv.CodeForbidden {
		t.Fatalf("error lost over ipc: %v", err)
	}

	want := []string{
		"ListAnchors", "PutAnchor tf k8s m", "DeleteAnchor tf k8s m", "ValidateAnchor k8s", "DriftAnchor k8s",
		"ListTables", "GetTable t", "PutTable tf t 10.0.0.0/8", "DriftTable t", "GetQoS", "PutQoS netops root",
		"ValidateQoS root", "DriftQoS", "Pending", "Confirm admin abc", "Rollback tf abc", "Confirm tf abc",
	}
	if strings.Join(f.calls, "|") != strings.Join(want, "|") {
		t.Fatalf("calls:\n%v\nwant:\n%v", f.calls, want)
	}
}

func TestTLSMaterial(t *testing.T) {
	m := api.Material{CertPEM: []byte("cert"), KeyPEM: []byte("key"), CAs: map[string][]byte{"default": []byte("ca")}}
	c := serve(t, &full{}, func() (api.Material, error) { return m, nil })
	got, err := c.TLSMaterial()
	if err != nil || string(got.CertPEM) != "cert" || string(got.CAs["default"]) != "ca" {
		t.Fatalf("material: %+v %v", got, err)
	}

	c = serve(t, &full{}, nil)
	var pe *priv.Error
	if _, err := c.TLSMaterial(); !errors.As(err, &pe) || pe.Code != priv.CodeInvalid {
		t.Fatalf("reload disabled: %v", err)
	}

	c = serve(t, &full{}, func() (api.Material, error) { return api.Material{}, errors.New("unreadable key") })
	if _, err := c.TLSMaterial(); !errors.As(err, &pe) || pe.Code != priv.CodeInternal {
		t.Fatalf("source error: %v", err)
	}
}

// Requests the client never sends, but a compromised network process could.
func TestMalformedRequests(t *testing.T) {
	f := &full{}
	c := serve(t, f, nil)
	for _, op := range []string{"put_anchor", "validate_anchor", "put_table", "put_qos", "validate_qos", "format_disk"} {
		err := c.call(request{Op: op}, nil)
		var pe *priv.Error
		if !errors.As(err, &pe) || pe.Code != priv.CodeInvalid {
			t.Errorf("%s without payload: %v", op, err)
		}
	}
	if len(f.calls) != 0 {
		t.Fatalf("malformed requests reached the backend: %v", f.calls)
	}
}

func TestBootstrapRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	in := Bootstrap{
		Listen:    "192.0.2.1:8443",
		TLS:       api.Material{CertPEM: []byte("c")},
		Clients:   json.RawMessage(`[{"name":"tf"}]`),
		RateLimit: 5, RateBurst: 7, TLSReload: time.Minute,
	}
	if err := SendBootstrap(&buf, in); err != nil {
		t.Fatal(err)
	}
	out, err := ReadBootstrap(&buf)
	if err != nil || out.Listen != in.Listen || string(out.Clients) != string(in.Clients) ||
		out.RateBurst != 7 || out.TLSReload != time.Minute || string(out.TLS.CertPEM) != "c" {
		t.Fatalf("bootstrap: %+v %v", out, err)
	}
	if _, err := ReadBootstrap(&buf); err == nil {
		t.Fatal("read from an empty stream succeeded")
	}
}

func TestWriteLimitAndBrokenConn(t *testing.T) {
	var buf bytes.Buffer
	if err := writeMsg(&buf, strings.Repeat("x", MaxMessage)); err == nil || buf.Len() != 0 {
		t.Fatalf("oversized write: %v (%d bytes written)", err, buf.Len())
	}
	if err := writeMsg(&buf, func() {}); err == nil {
		t.Fatal("unmarshalable value written")
	}

	// The server side goes away: the client reports a read error.
	a, s := net.Pipe()
	go func() {
		var r request
		_ = readMsg(s, &r)
		_ = s.Close()
	}()
	if _, err := NewClient(a).ListAnchors(context.Background()); err == nil || !strings.Contains(err.Error(), "ipc read") {
		t.Fatalf("closed server: %v", err)
	}
	// Closed connection: write error.
	_ = a.Close()
	if _, err := NewClient(a).ListAnchors(context.Background()); err == nil || !strings.Contains(err.Error(), "ipc write") {
		t.Fatalf("closed client: %v", err)
	}
}

// A response with another request's id is refused (no confusion between
// requests if the stream ever desynchronised).
func TestResponseIDMismatch(t *testing.T) {
	a, s := net.Pipe()
	defer a.Close()
	go func() {
		var r request
		_ = readMsg(s, &r)
		_ = writeMsg(s, response{ID: r.ID + 1})
	}()
	if _, err := NewClient(a).ListAnchors(context.Background()); err == nil || !strings.Contains(err.Error(), "response") {
		t.Fatalf("mismatched id accepted: %v", err)
	}
}

func TestServeEnds(t *testing.T) {
	// EOF: clean end.
	if err := Serve(context.Background(), &bytes.Buffer{}, &full{}, nil); err != nil {
		t.Fatalf("EOF: %v", err)
	}
	// Garbage: an error.
	var buf bytes.Buffer
	buf.Write([]byte{0, 0, 0, 3, 'x', 'y', 'z'})
	if err := Serve(context.Background(), &buf, &full{}, nil); err == nil {
		t.Fatal("garbage request accepted")
	}
}

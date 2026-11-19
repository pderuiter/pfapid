// Package ipc connects the unprivileged network process to the privileged
// process over a socketpair: 4-byte big-endian length + JSON, at most
// MaxMessage bytes. Requests are served strictly one at a time.
package ipc

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/pderuiter/pfapid/internal/api"

	"github.com/pderuiter/pfapid/internal/model"
	"github.com/pderuiter/pfapid/internal/priv"
)

const MaxMessage = 4 << 20

func writeMsg(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(b) > MaxMessage {
		return fmt.Errorf("ipc: message of %d bytes exceeds limit", len(b))
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b))) // #nosec G115 -- bounded by MaxMessage above
	if _, err := w.Write(append(hdr[:], b...)); err != nil {
		return err
	}
	return nil
}

func readMsg(r io.Reader, v any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n > MaxMessage {
		return fmt.Errorf("ipc: message of %d bytes exceeds limit", n)
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(r, b); err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}

// Bootstrap is the first and only message the privileged side sends
// unprompted: everything the network process needs, so that it never has
// to open a file (it runs pledge("stdio inet")).
type Bootstrap struct {
	Listen    string          `json:"listen"`
	TLS       api.Material    `json:"tls"`
	Clients   json.RawMessage `json:"clients"`
	RateLimit float64         `json:"rate_limit"`
	RateBurst int             `json:"rate_burst"`
	// TLSReload is how often the network process asks for fresh TLS
	// material (certificate rotation); 0 disables it.
	TLSReload time.Duration `json:"tls_reload"`
}

// TLSSource reads the current TLS material from disk (privileged side).
type TLSSource func() (api.Material, error)

func SendBootstrap(w io.Writer, b Bootstrap) error { return writeMsg(w, b) }
func ReadBootstrap(r io.Reader) (Bootstrap, error) {
	var b Bootstrap
	err := readMsg(r, &b)
	return b, err
}

type request struct {
	ID       uint64            `json:"id"`
	Op       string            `json:"op"`
	Actor    string            `json:"actor,omitempty"`
	Admin    bool              `json:"admin,omitempty"`
	Name     string            `json:"name,omitempty"`
	ChangeID string            `json:"change_id,omitempty"`
	Anchor   *model.Anchor     `json:"anchor,omitempty"`
	Table    *model.Table      `json:"table,omitempty"`
	QoS      *model.QoS        `json:"qos,omitempty"`
	Pre      priv.Precondition `json:"pre,omitempty"`
}

type response struct {
	ID     uint64          `json:"id"`
	Err    *priv.Error     `json:"error,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
}

// Serve answers requests from conn using b until conn is closed.
func Serve(ctx context.Context, conn io.ReadWriter, b priv.Backend, tlsSrc TLSSource) error {
	for {
		var req request
		if err := readMsg(conn, &req); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		res, err := handle(ctx, b, tlsSrc, req)
		if err := writeMsg(conn, makeResponse(req.ID, res, err)); err != nil {
			return err
		}
	}
}

// handle answers one request: the TLS material from tlsSrc, anything else
// from the backend.
func handle(ctx context.Context, b priv.Backend, tlsSrc TLSSource, req request) (any, error) {
	if req.Op != "tls_material" {
		return dispatch(ctx, b, req)
	}
	if tlsSrc == nil {
		return nil, &priv.Error{Code: priv.CodeInvalid, Msg: "tls reload not enabled"}
	}
	return tlsSrc()
}

func makeResponse(id uint64, res any, err error) response {
	resp := response{ID: id}
	if err != nil {
		resp.Err = priv.AsError(err)
		return resp
	}
	if res == nil {
		return resp
	}
	raw, merr := json.Marshal(res)
	if merr != nil {
		resp.Err = priv.AsError(merr)
	} else {
		resp.Result = raw
	}
	return resp
}

func dispatch(ctx context.Context, b priv.Backend, r request) (any, error) {
	need := func(ok bool) error {
		if !ok {
			return &priv.Error{Code: priv.CodeInvalid, Msg: "malformed ipc request for " + r.Op}
		}
		return nil
	}
	switch r.Op {
	case "list_anchors":
		return b.ListAnchors(ctx)
	case "get_anchor":
		return b.GetAnchor(ctx, r.Name)
	case "put_anchor":
		if err := need(r.Anchor != nil); err != nil {
			return nil, err
		}
		return b.PutAnchor(ctx, r.Actor, *r.Anchor, r.Pre)
	case "delete_anchor":
		return b.DeleteAnchor(ctx, r.Actor, r.Name, r.Pre)
	case "validate_anchor":
		if err := need(r.Anchor != nil); err != nil {
			return nil, err
		}
		return b.ValidateAnchor(ctx, *r.Anchor)
	case "drift_anchor":
		return b.DriftAnchor(ctx, r.Name)
	case "list_tables":
		return b.ListTables(ctx)
	case "get_table":
		return b.GetTable(ctx, r.Name)
	case "put_table":
		if err := need(r.Table != nil); err != nil {
			return nil, err
		}
		return b.PutTable(ctx, r.Actor, *r.Table, r.Pre)
	case "drift_table":
		return b.DriftTable(ctx, r.Name)
	case "get_qos":
		return b.GetQoS(ctx)
	case "put_qos":
		if err := need(r.QoS != nil); err != nil {
			return nil, err
		}
		return b.PutQoS(ctx, r.Actor, *r.QoS, r.Pre)
	case "validate_qos":
		if err := need(r.QoS != nil); err != nil {
			return nil, err
		}
		return b.ValidateQoS(ctx, *r.QoS)
	case "drift_qos":
		return b.DriftQoS(ctx)
	case "pending":
		return b.Pending(ctx)
	case "confirm":
		return nil, b.Confirm(ctx, r.Actor, r.ChangeID, r.Admin)
	case "rollback":
		return nil, b.Rollback(ctx, r.Actor, r.ChangeID, r.Admin)
	}
	return nil, &priv.Error{Code: priv.CodeInvalid, Msg: "unknown op " + r.Op}
}

// Client implements priv.Backend over the socket.
type Client struct {
	mu   sync.Mutex
	conn io.ReadWriter
	next uint64
}

func NewClient(conn io.ReadWriter) *Client { return &Client{conn: conn} }

func (c *Client) call(r request, out any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.next++
	r.ID = c.next
	if err := writeMsg(c.conn, r); err != nil {
		return fmt.Errorf("ipc write: %w", err)
	}
	var resp response
	if err := readMsg(c.conn, &resp); err != nil {
		return fmt.Errorf("ipc read: %w", err)
	}
	if resp.ID != r.ID {
		return fmt.Errorf("ipc: response %d for request %d", resp.ID, r.ID)
	}
	if resp.Err != nil {
		return resp.Err
	}
	if out != nil && len(resp.Result) > 0 {
		return json.Unmarshal(resp.Result, out)
	}
	return nil
}

func (c *Client) ListAnchors(context.Context) ([]string, error) {
	var v []string
	return v, c.call(request{Op: "list_anchors"}, &v)
}
func (c *Client) GetAnchor(_ context.Context, name string) (priv.AnchorState, error) {
	var v priv.AnchorState
	return v, c.call(request{Op: "get_anchor", Name: name}, &v)
}
func (c *Client) PutAnchor(_ context.Context, actor string, a model.Anchor, pre priv.Precondition) (priv.ChangeInfo, error) {
	var v priv.ChangeInfo
	return v, c.call(request{Op: "put_anchor", Actor: actor, Anchor: &a, Pre: pre}, &v)
}
func (c *Client) DeleteAnchor(_ context.Context, actor, name string, pre priv.Precondition) (priv.ChangeInfo, error) {
	var v priv.ChangeInfo
	return v, c.call(request{Op: "delete_anchor", Actor: actor, Name: name, Pre: pre}, &v)
}
func (c *Client) ValidateAnchor(_ context.Context, a model.Anchor) (priv.ValidateResult, error) {
	var v priv.ValidateResult
	return v, c.call(request{Op: "validate_anchor", Anchor: &a}, &v)
}
func (c *Client) DriftAnchor(_ context.Context, name string) (priv.DriftResult, error) {
	var v priv.DriftResult
	return v, c.call(request{Op: "drift_anchor", Name: name}, &v)
}
func (c *Client) ListTables(context.Context) ([]string, error) {
	var v []string
	return v, c.call(request{Op: "list_tables"}, &v)
}
func (c *Client) GetTable(_ context.Context, name string) (priv.TableState, error) {
	var v priv.TableState
	return v, c.call(request{Op: "get_table", Name: name}, &v)
}
func (c *Client) PutTable(_ context.Context, actor string, t model.Table, pre priv.Precondition) (priv.ChangeInfo, error) {
	var v priv.ChangeInfo
	return v, c.call(request{Op: "put_table", Actor: actor, Table: &t, Pre: pre}, &v)
}
func (c *Client) DriftTable(_ context.Context, name string) (priv.DriftResult, error) {
	var v priv.DriftResult
	return v, c.call(request{Op: "drift_table", Name: name}, &v)
}
func (c *Client) GetQoS(context.Context) (priv.QoSState, error) {
	var v priv.QoSState
	return v, c.call(request{Op: "get_qos"}, &v)
}
func (c *Client) PutQoS(_ context.Context, actor string, q model.QoS, pre priv.Precondition) (priv.ChangeInfo, error) {
	var v priv.ChangeInfo
	return v, c.call(request{Op: "put_qos", Actor: actor, QoS: &q, Pre: pre}, &v)
}
func (c *Client) ValidateQoS(_ context.Context, q model.QoS) (priv.ValidateResult, error) {
	var v priv.ValidateResult
	return v, c.call(request{Op: "validate_qos", QoS: &q}, &v)
}
func (c *Client) DriftQoS(context.Context) (priv.DriftResult, error) {
	var v priv.DriftResult
	return v, c.call(request{Op: "drift_qos"}, &v)
}

// TLSMaterial asks the privileged side for the current TLS files.
func (c *Client) TLSMaterial() (api.Material, error) {
	var v api.Material
	return v, c.call(request{Op: "tls_material"}, &v)
}

func (c *Client) Pending(context.Context) (*priv.ChangeInfo, error) {
	var v *priv.ChangeInfo
	return v, c.call(request{Op: "pending"}, &v)
}
func (c *Client) Confirm(_ context.Context, actor, id string, admin bool) error {
	return c.call(request{Op: "confirm", Actor: actor, ChangeID: id, Admin: admin}, nil)
}
func (c *Client) Rollback(_ context.Context, actor, id string, admin bool) error {
	return c.call(request{Op: "rollback", Actor: actor, ChangeID: id, Admin: admin}, nil)
}

var _ priv.Backend = (*Client)(nil)
var _ priv.Backend = (*priv.Server)(nil)

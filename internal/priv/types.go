package priv

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/pderuiter/pfapid/internal/model"
)

// Error codes. They travel over IPC as strings and the API maps them to
// HTTP status codes.
const (
	CodeInvalid      = "invalid"      // 400
	CodeNotFound     = "not_found"    // 404
	CodeConflict     = "conflict"     // 409: another change is pending
	CodePrecondition = "precondition" // 412: ETag mismatch / exists / missing
	CodePFRejected   = "pf_rejected"  // 422: pfctl refused the rendered rules
	CodeForbidden    = "forbidden"    // 403
	CodeInternal     = "internal"     // 500
)

// Error is the only error type the privileged side returns to callers.
type Error struct {
	Code string `json:"code"`
	Msg  string `json:"message"`
}

func (e *Error) Error() string { return e.Code + ": " + e.Msg }

func errf(code, format string, a ...any) *Error {
	return &Error{Code: code, Msg: fmt.Sprintf(format, a...)}
}

// AsError converts any error into an *Error (unknown errors become internal).
func AsError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	if errors.Is(err, model.ErrInvalid) {
		return &Error{Code: CodeInvalid, Msg: err.Error()}
	}
	return &Error{Code: CodeInternal, Msg: err.Error()}
}

type AnchorState struct {
	Anchor        model.Anchor `json:"anchor"`
	ETag          string       `json:"etag"`
	PendingChange string       `json:"pending_change,omitempty"`
}

type TableState struct {
	Table         model.Table `json:"table"`
	ETag          string      `json:"etag"`
	PendingChange string      `json:"pending_change,omitempty"`
}

type QoSState struct {
	QoS           model.QoS `json:"qos"`
	ETag          string    `json:"etag"`
	PendingChange string    `json:"pending_change,omitempty"`
}

// Precondition carries HTTP-style conditional semantics: updates and deletes
// need IfMatch (the current ETag); creates need IfNoneMatch.
type Precondition struct {
	IfMatch     string `json:"if_match,omitempty"`
	IfNoneMatch bool   `json:"if_none_match,omitempty"`
}

// ChangeInfo describes an applied but unconfirmed change.
type ChangeInfo struct {
	ID       string    `json:"id"`
	Actor    string    `json:"actor"`
	Kind     string    `json:"kind"` // anchor | table | qos
	Name     string    `json:"name"`
	Op       string    `json:"op"` // put | delete
	Deadline time.Time `json:"deadline"`
	// ETag the object will have once confirmed ("" for a delete).
	ETag string `json:"etag,omitempty"`
}

type ValidateResult struct {
	Rendered   []string `json:"rendered"`
	Normalised []string `json:"normalised"`
}

type DriftResult struct {
	InSync   bool     `json:"in_sync"`
	Expected []string `json:"expected"`
	Live     []string `json:"live"`
}

// Backend is what the API needs from the privileged side. *Server
// implements it directly; the ipc client implements it over the socket.
type Backend interface {
	ListAnchors(ctx context.Context) ([]string, error)
	GetAnchor(ctx context.Context, name string) (AnchorState, error)
	PutAnchor(ctx context.Context, actor string, a model.Anchor, pre Precondition) (ChangeInfo, error)
	DeleteAnchor(ctx context.Context, actor, name string, pre Precondition) (ChangeInfo, error)
	ValidateAnchor(ctx context.Context, a model.Anchor) (ValidateResult, error)
	DriftAnchor(ctx context.Context, name string) (DriftResult, error)
	ListTables(ctx context.Context) ([]string, error)
	GetTable(ctx context.Context, name string) (TableState, error)
	PutTable(ctx context.Context, actor string, t model.Table, pre Precondition) (ChangeInfo, error)
	DriftTable(ctx context.Context, name string) (DriftResult, error)
	GetQoS(ctx context.Context) (QoSState, error)
	PutQoS(ctx context.Context, actor string, q model.QoS, pre Precondition) (ChangeInfo, error)
	ValidateQoS(ctx context.Context, q model.QoS) (ValidateResult, error)
	DriftQoS(ctx context.Context) (DriftResult, error)
	Pending(ctx context.Context) (*ChangeInfo, error)
	Confirm(ctx context.Context, actor, id string, admin bool) error
	Rollback(ctx context.Context, actor, id string, admin bool) error
}

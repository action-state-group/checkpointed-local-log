package cll

import "errors"

// Error classes, one per code in docs/backend-contract.md. Errors wrap one of
// these, so callers test them with errors.Is.
var (
	ErrNotFound   = errors.New("cll: not found")
	ErrInvalid    = errors.New("cll: invalid")
	ErrCorrupt    = errors.New("cll: corrupt")
	ErrClosed     = errors.New("cll: closed")
	ErrContention = errors.New("cll: contention")
	ErrRejected   = errors.New("cll: rejected")
	// ErrUnsupported reports an operation the store does not offer, such as
	// appending a bare identity to a store that needs a full record first.
	ErrUnsupported = errors.New("cll: unsupported")
)

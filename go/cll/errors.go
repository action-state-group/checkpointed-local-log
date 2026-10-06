package cll

import "errors"

var (
	ErrNotFound   = errors.New("cll: not found")
	ErrInvalid    = errors.New("cll: invalid")
	ErrCorrupt    = errors.New("cll: corrupt")
	ErrClosed     = errors.New("cll: closed")
	ErrContention = errors.New("cll: contention")
	ErrRejected   = errors.New("cll: rejected")
)

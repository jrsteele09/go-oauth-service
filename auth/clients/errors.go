package clients

import "errors"

var (
	ErrInvalidClient       = errors.New("invalid client")
	ErrInvalidClientID     = errors.New("invalid client id")
	ErrInvalidClientSecret = errors.New("invalid client secret")
	ErrInvalidScope        = errors.New("invalid scope for client")
)

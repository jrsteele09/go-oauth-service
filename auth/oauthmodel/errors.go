package oauthmodel

import "errors"

var (
	// Authorization errors
	ErrInvalidGrant             = errors.New("invalid grant")
	ErrInvalidAuthorizationCode = errors.New("invalid authorization code")
	ErrInvalidCodeChallenge     = errors.New("invalid code challenge")
	ErrInvalidRequest           = errors.New("invalid request")
	ErrInvalidResponseMode      = errors.New("invalid response mode")
	ErrInvalidResponseType      = errors.New("invalid response type")
	ErrInvalidRedirectURI       = errors.New("invalid redirect URI")
)

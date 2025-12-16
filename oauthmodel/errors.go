package oauthmodel

import "errors"

var (
	ErrInvalidCodeChallenge       = errors.New("invalid code challenge")
	ErrClientTenantsMismatch      = errors.New("client does not match tenant")
	ErrInvalidCodeChallengeMethod = errors.New("invalid code challenge method")
	ErrInvalidRedirectUri         = errors.New("invalid or no redirect uri")
	ErrInvalidResponseMode        = errors.New("invalid response mode")
	ErrInvalidResponseType        = errors.New("unsupported response type")
)

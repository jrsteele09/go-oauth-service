package auth

import "errors"

var (
	ErrInvalidAccessToken = errors.New("invalid access token")
	ErrSessionNotFound    = errors.New("session not found")
	ErrSessionExpired     = errors.New("session expired")
)

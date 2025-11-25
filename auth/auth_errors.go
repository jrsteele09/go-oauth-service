package auth

import "errors"

var (
	ErrInvalidClientID        = errors.New("invalid client id")
	ErrInvalidTenant          = errors.New("invalid tenant")
	ErrInvalidAccessToken     = errors.New("invalid access token")
	ErrUserNotFound           = errors.New("user not found")
	ErrUserBlocked            = errors.New("user blocked")
	ErrUserUnverified         = errors.New("user not verified")
	ErrUserPasswordsDontMatch = errors.New("user passwords not matched")
)

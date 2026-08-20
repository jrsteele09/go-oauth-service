package users

import "errors"

var (
	ErrUserNotFound           = errors.New("user not found")
	ErrUserBlocked            = errors.New("user is blocked")
	ErrUserNotVerified        = errors.New("user is not verified")
	ErrUserPasswordsDontMatch = errors.New("user passwords not matched")
	ErrInvalidCredentials     = errors.New("invalid credentials")
)

package auth

import "errors"

var (
	InvalidClientIDErr        = errors.New("invalid client id")
	InvalidTenantErr          = errors.New("invalid tenant")
	InvalidAccessTokenErr     = errors.New("invalid access token")
	UserNotFoundErr           = errors.New("user not found")
	UserBlockedErr            = errors.New("user blocked")
	UserUnverifiedErr         = errors.New("user not verified")
	UserPasswordsDontMatchErr = errors.New("user passwords not matched")
)

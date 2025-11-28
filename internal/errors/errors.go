package errors

import (
	"errors"
	"fmt"
)

// Common error types for the OAuth2 server
var (
	// Authentication errors
	ErrInvalidCredentials = errors.New("invalid credentials")
	ErrUserBlocked        = errors.New("user is blocked")
	ErrUserNotVerified    = errors.New("user is not verified")
	ErrUserNotFound       = errors.New("user not found")

	// Token errors
	ErrInvalidToken        = errors.New("invalid token")
	ErrTokenExpired        = errors.New("token expired")
	ErrTokenRevoked        = errors.New("token revoked")
	ErrInvalidRefreshToken = errors.New("invalid refresh token")
	ErrRefreshTokenExpired = errors.New("refresh token expired")

	// Client errors
	ErrInvalidClient       = errors.New("invalid client")
	ErrInvalidClientSecret = errors.New("invalid client secret")
	ErrInvalidScope        = errors.New("invalid scope")
	ErrInvalidRedirectURI  = errors.New("invalid redirect URI")

	// Authorization errors
	ErrInvalidGrant             = errors.New("invalid grant")
	ErrInvalidAuthorizationCode = errors.New("invalid authorization code")
	ErrInvalidCodeChallenge     = errors.New("invalid code challenge")
	ErrInvalidRequest           = errors.New("invalid request")

	// Tenant errors
	ErrTenantNotFound     = errors.New("tenant not found")
	ErrInvalidTenant      = errors.New("invalid tenant")
	ErrUnauthorizedTenant = errors.New("unauthorized for tenant")

	// Session errors
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")

	// General errors
	ErrNotFound    = errors.New("not found")
	ErrInternal    = errors.New("internal error")
	ErrUnsupported = errors.New("unsupported operation")
)

// Wrapf wraps an error with context using fmt.Errorf
func Wrapf(err error, format string, args ...interface{}) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf(format+": %w", append(args, err)...)
}

// Is reports whether any error in err's chain matches target
func Is(err, target error) bool {
	return errors.Is(err, target)
}

// As finds the first error in err's chain that matches target
func As(err error, target interface{}) bool {
	return errors.As(err, target)
}

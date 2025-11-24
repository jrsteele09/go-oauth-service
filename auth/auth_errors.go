package auth

import "github.com/pkg/errors"

var (
	InvalidClientIDErr            = errors.New("invalid client id")
	InvalidCodeChallengeErr       = errors.New("invalid code challenge")
	InvalidCodeChallengeMethodErr = errors.New("invalid code challenge method")
	InvalidRedirectUriErr         = errors.New("invalid or no redirect uri")
	InvalidResponseModeErr        = errors.New("invalid response mode")
	InvalidResponseTypeErr        = errors.New("unsupported response type")
	InvalidTenantErr              = errors.New("invalid tenant")
	ClientTenantsMismatchErr      = errors.New("client does not match tenant")
	InvalidAccessTokenErr         = errors.New("invalid access token")
	UserNotFoundErr               = errors.New("user not found")
	UserBlockedErr                = errors.New("user blocked")
	UserUnverifiedErr             = errors.New("user not verified")
	UserPasswordsDontMatchErr     = errors.New("user passwords not matched")
)

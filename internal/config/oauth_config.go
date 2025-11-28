package config

import "time"

type OAuthConfig interface {
	GetAuthCodeTimeout() time.Duration
	GetCodeGenerationLength() int
	GetRefreshTokenLength() int
	GetDefaultAccessTokenExpiry() time.Duration
	GetDefaultIDTokenExpiry() time.Duration
	GetDefaultRefreshTokenExpiry() time.Duration
}

type OAuth struct{}

var _ OAuthConfig = OAuth{}

func (OAuth) GetAuthCodeTimeout() time.Duration {
	return 15 * time.Minute
}

func (OAuth) GetCodeGenerationLength() int {
	return 32
}

func (OAuth) GetRefreshTokenLength() int {
	return 32 // 32 bytes = 256 bits
}

func (OAuth) GetDefaultAccessTokenExpiry() time.Duration {
	return 1 * time.Hour
}

func (OAuth) GetDefaultIDTokenExpiry() time.Duration {
	return 1 * time.Hour
}

func (OAuth) GetDefaultRefreshTokenExpiry() time.Duration {
	return 7 * 24 * time.Hour // 7 days
}

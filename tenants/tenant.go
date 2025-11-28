package tenants

import "time"

// Tenant represents a multi-tenant organization (domain entity).
// This is the core domain model containing only identity and basic metadata.
type Tenant struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Domain string `json:"domain"`

	// Embedded configuration and keys
	// These are separated concerns but kept together for convenience
	Config TenantConfig `json:"config"`
	Keys   TenantKeys   `json:"keys"`
}

// TenantConfig holds OAuth2/OIDC configuration specific to a tenant.
// This separates protocol configuration from the domain entity.
type TenantConfig struct {
	Issuer   string `json:"issuer"`   // OAuth2 issuer URL
	Audience string `json:"audience"` // OAuth2 audience

	// Token expiry configuration (if zero, defaults are used from global OAuthConfig)
	AccessTokenExpiry  time.Duration `json:"access_token_expiry,omitempty"`
	IDTokenExpiry      time.Duration `json:"id_token_expiry,omitempty"`
	RefreshTokenExpiry time.Duration `json:"refresh_token_expiry,omitempty"`
}

// TenantKeys holds cryptographic key material for JWT signing.
// This separates security-sensitive data from domain and configuration.
// All tenants use RS256 (RSA with SHA-256) signing algorithm.
type TenantKeys struct {
	KeyID         string `json:"key_id"`          // JWT kid claim
	PrivateKeyPEM string `json:"private_key_pem"` // PEM-encoded RSA private key
	PublicKeyPEM  string `json:"public_key_pem"`  // PEM-encoded RSA public key
}

// GetAccessTokenExpiry returns the tenant's access token expiry or the default if not set.
func (tc *TenantConfig) GetAccessTokenExpiry(defaultExpiry time.Duration) time.Duration {
	if tc.AccessTokenExpiry > 0 {
		return tc.AccessTokenExpiry
	}
	return defaultExpiry
}

// GetIDTokenExpiry returns the tenant's ID token expiry or the default if not set.
func (tc *TenantConfig) GetIDTokenExpiry(defaultExpiry time.Duration) time.Duration {
	if tc.IDTokenExpiry > 0 {
		return tc.IDTokenExpiry
	}
	return defaultExpiry
}

// GetRefreshTokenExpiry returns the tenant's refresh token expiry or the default if not set.
func (tc *TenantConfig) GetRefreshTokenExpiry(defaultExpiry time.Duration) time.Duration {
	if tc.RefreshTokenExpiry > 0 {
		return tc.RefreshTokenExpiry
	}
	return defaultExpiry
}

// HasKeys returns true if the tenant has key material configured.
func (tk *TenantKeys) HasKeys() bool {
	return tk.PrivateKeyPEM != "" && tk.PublicKeyPEM != ""
}

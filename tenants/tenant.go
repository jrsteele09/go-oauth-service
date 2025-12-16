package tenants

import (
	"fmt"
	"time"

	"github.com/jrsteele09/go-auth-server/token/keys"
)

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
	Issuer   string `json:"issuer"`    // OAuth2 issuer URL
	Audience string `json:"audience"`  // OAuth2 audience
	LoginURL string `json:"login_url"` // Custom login URL for the tenant

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

// New creates a new tenant with the specified parameters and generates signing keys.
// It returns the tenant with generated RSA key material for JWT signing.
func New(id, name, domain string, config TenantConfig) (*Tenant, error) {
	tenant := &Tenant{
		ID:     id,
		Name:   name,
		Domain: domain,
		Config: config,
	}

	keyPair, err := keys.GenerateKeysForTenant(tenant.ID + "-key")
	if err != nil {
		return nil, fmt.Errorf("failed to generate keys for tenant %s: %w", tenant.ID, err)
	}

	privatePEM, err := keyPair.ExportPrivateKeyPEM()
	if err != nil {
		return nil, fmt.Errorf("failed to export private key: %w", err)
	}

	publicPEM, err := keyPair.ExportPublicKeyPEM()
	if err != nil {
		return nil, fmt.Errorf("failed to export public key: %w", err)
	}

	tenant.Keys.KeyID = keyPair.KeyID
	tenant.Keys.PrivateKeyPEM = privatePEM
	tenant.Keys.PublicKeyPEM = publicPEM
	return tenant, nil
}

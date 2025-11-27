package tenants

import "time"

// SignerType represents the type of signing algorithm for JWT tokens
type SignerType string

const (
	// SignerTypeHMAC uses symmetric HMAC-SHA256 signing (HS256)
	SignerTypeHMAC SignerType = "HMAC"

	// SignerTypeRS256 uses RSA with SHA-256 (RS256) - 2048-bit key
	SignerTypeRS256 SignerType = "RS256"

	// SignerTypeRS384 uses RSA with SHA-384 (RS384) - 3072-bit key
	SignerTypeRS384 SignerType = "RS384"

	// SignerTypeRS512 uses RSA with SHA-512 (RS512) - 4096-bit key
	SignerTypeRS512 SignerType = "RS512"

	// SignerTypeES256 uses ECDSA with SHA-256 and P-256 curve (ES256)
	SignerTypeES256 SignerType = "ES256"

	// SignerTypeES384 uses ECDSA with SHA-384 and P-384 curve (ES384)
	SignerTypeES384 SignerType = "ES384"

	// SignerTypeES512 uses ECDSA with SHA-512 and P-521 curve (ES512)
	SignerTypeES512 SignerType = "ES512"
)

// Tenant represents a multi-tenant organization with its own OAuth2 configuration.
// Each tenant can have its own issuer, audience, and signing key for token isolation.
type Tenant struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Domain     string     `json:"domain"`
	Issuer     string     `json:"issuer"`      // OAuth2 issuer URL (e.g., "https://tenant-a.auth.example.com")
	Audience   string     `json:"audience"`    // OAuth2 audience (e.g., "https://tenant-a.api.example.com")
	SignerType SignerType `json:"signer_type"` // Type of signing algorithm (HMAC, RS256, ES256, etc.)
	KeyID      string     `json:"key_id"`      // Unique identifier for the signing key (kid claim in JWT header)

	// Key material for signing tokens - the actual keys/secrets
	// For HMAC: HMACSecret contains the symmetric key
	// For RSA/ECDSA: PrivateKeyPEM and PublicKeyPEM contain PEM-encoded keys
	HMACSecret    string `json:"hmac_secret,omitempty"`     // HMAC symmetric secret (for HS256)
	PrivateKeyPEM string `json:"private_key_pem,omitempty"` // PEM-encoded private key (for RS*, ES*)
	PublicKeyPEM  string `json:"public_key_pem,omitempty"`  // PEM-encoded public key (for RS*, ES*)

	// Token expiry configuration - allows per-tenant customization
	AccessTokenExpiry  time.Duration `json:"access_token_expiry,omitempty"`  // How long access tokens are valid (0 = use default)
	IDTokenExpiry      time.Duration `json:"id_token_expiry,omitempty"`      // How long ID tokens are valid (0 = use default)
	RefreshTokenExpiry time.Duration `json:"refresh_token_expiry,omitempty"` // How long refresh tokens are valid (0 = use default)
}

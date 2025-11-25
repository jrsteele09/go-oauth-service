package tenants

// Tenant represents a multi-tenant organization with its own OAuth2 configuration.
// Each tenant can have its own issuer, audience, and signing key for token isolation.
type Tenant struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Domain   string `json:"domain"`
	Issuer   string `json:"issuer"`    // OAuth2 issuer URL (e.g., "https://tenant-a.auth.example.com")
	Audience string `json:"audience"`  // OAuth2 audience (e.g., "https://tenant-a.api.example.com")
	SignerID string `json:"signer_id"` // Reference to signing key (for key rotation)
}

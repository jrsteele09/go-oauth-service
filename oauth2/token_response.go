package oauth2

// TokenResponse represents the response from an OAuth2 token request.
// This is the standard OAuth2 token endpoint response format as defined in RFC 6749.
// Returned from the /token endpoint for all grant types.
type TokenResponse struct {
	// AccessToken is the JWT token used to access protected resources.
	// Example: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
	// Usage: Include in Authorization header: "Bearer <access_token>"
	// Lifespan: Short-lived (typically 15 minutes - 1 hour)
	AccessToken *string `json:"access_token,omitempty"`

	// IdToken is the OpenID Connect ID token containing user identity information.
	// Example: "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..."
	// Usage: Client validates and extracts user claims (sub, email, name, etc.)
	// Only present: When "openid" scope was requested
	IdToken *string `json:"id_token,omitempty"`

	// TokenType indicates how to use the access token (always "bearer" in this implementation).
	// Example: "bearer"
	// Standard: OAuth2 spec requires this field
	// Usage: Tells client to use "Authorization: Bearer <token>" header
	TokenType string `json:"token_type,omitempty"`

	// ExpiresIn is the lifetime in seconds of the access token.
	// Example: 900 (for 15 minutes)
	// Usage: Client should refresh token before expiration
	// Note: This is a hint - actual expiration is in the JWT's "exp" claim
	ExpiresIn int `json:"expires_in,omitempty"`

	// RefreshToken is an opaque token used to obtain new access tokens.
	// Example: "tGzv3JOkF0XG5Qx2TlKWIA"
	// Usage: Send to /token endpoint with grant_type=refresh_token
	// Lifespan: Long-lived (typically 7-30 days)
	// Security: Should be stored securely, rotates on each use
	RefreshToken *string `json:"refresh_token,omitempty"`

	// Scope indicates the access token's granted permissions.
	// Example: "openid profile email api.read"
	// Usage: Space-separated list of scopes
	// Note: May be less than requested if some scopes were denied
	Scope string `json:"scope,omitempty"`
}

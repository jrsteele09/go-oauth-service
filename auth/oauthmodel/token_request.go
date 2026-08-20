package oauthmodel

// TokenRequest holds parameters for the OAuth2 token request.
// This represents the request body sent to the /token endpoint.
// Supports multiple grant types: authorization_code, refresh_token, client_credentials
type TokenRequest struct {
	TenantID string
	// ClientID identifies the OAuth2 client making the request.
	// Required: Yes (for all grant types)
	// Example: "web-app-client"
	ClientID string

	// ClientSecret is the secret credential for confidential clients.
	// Required: Yes for confidential clients, No for public clients
	// Example: "super-secret-value"
	// Security: Never log or expose this value
	ClientSecret string

	// Code is the authorization code received from the authorization endpoint.
	// Required: Yes (only for authorization_code grant)
	// Example: "SplxlOBeZQQYbYS6WxSbIA"
	// Usage: Exchanged once for tokens, then becomes invalid
	Code string

	// CodeVerifier is the PKCE code verifier that matches the code_challenge.
	// Required: Yes (if PKCE was used in authorization request)
	// Example: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	// Validation: Server compares SHA256(code_verifier) with stored code_challenge
	CodeVerifier string

	// RefreshToken is used to obtain new access tokens without re-authentication.
	// Required: Yes (only for refresh_token grant)
	// Example: "tGzv3JOkF0XG5Qx2TlKWIA"
	// Behavior: Typically rotated - old refresh token invalidated, new one issued
	RefreshToken string
}

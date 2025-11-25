package oauth2

// ResponseType represents the OAuth 2.0 response type.
// Determines what is returned from the authorization endpoint.
type ResponseType string

const (
	// CodeResponseType indicates the authorization code flow.
	// Used in: Authorization Code Flow (most secure, requires server-side client)
	// Returns an authorization code that must be exchanged for tokens at the token endpoint.
	// Example: /oauth/authorize?response_type=code&client_id=...
	CodeResponseType ResponseType = "code"
)

// ResponseModeType denotes how the authorization response parameters are returned to the client.
// Determines the mechanism used to send the auth code/error back to the redirect_uri.
type ResponseModeType string

const (
	// QueryResponseMode returns parameters in the URL query string.
	// Used in: Standard Authorization Code Flow
	// Example: https://client.example.com/callback?code=ABC123&state=xyz
	// Security: Parameters visible in browser history and server logs
	QueryResponseMode ResponseModeType = "query"

	// FragmentResponseMode returns parameters in the URL fragment (after #).
	// Used in: Implicit Flow (deprecated), some SPA scenarios
	// Example: https://client.example.com/callback#token=ABC123&state=xyz
	// Security: Fragment not sent to server, only accessible via JavaScript
	FragmentResponseMode ResponseModeType = "fragment"

	// FormPostResponseMode returns parameters via HTTP POST with auto-submitting HTML form.
	// Used in: Enhanced security scenarios, prevents exposure in URL
	// Example: Server returns HTML with <form method="post"> that auto-submits
	// Security: Parameters not in URL, safer for browser history
	FormPostResponseMode ResponseModeType = "form_post"
)

// CodeMethodType represents the PKCE (Proof Key for Code Exchange) challenge method.
// Used to prevent authorization code interception attacks (especially for public clients).
type CodeMethodType string

const (
	// CodeMethodTypeS256 indicates SHA-256 hashing is used for the code challenge.
	// Used in: PKCE flow (required for public clients like SPAs/mobile apps)
	// Client sends: code_challenge = BASE64URL(SHA256(code_verifier))
	// Server validates: SHA256(provided code_verifier) == stored code_challenge
	// Security: Most secure PKCE method, prevents code interception
	CodeMethodTypeS256 CodeMethodType = "S256"

	// CodeMethodTypeNone (labeled "plain") means no hashing, code_verifier sent directly.
	// Used in: Legacy PKCE implementations (not recommended)
	// Client sends: code_challenge = code_verifier (plaintext)
	// Server validates: provided code_verifier == stored code_challenge
	// Security: Weaker than S256, only protects against passive attacks
	CodeMethodTypeNone CodeMethodType = "plain"
)

// GrantType represents the OAuth 2.0 grant type used at the token endpoint.
// Determines what credentials are required to obtain tokens.
type GrantType string

const (
	// AuthorizationCodeGrant exchanges an authorization code for tokens.
	// Used in: Standard Authorization Code Flow
	// Token request includes: code, client_id, client_secret, redirect_uri, code_verifier (if PKCE)
	// Returns: access_token, id_token, refresh_token (if requested)
	AuthorizationCodeGrant GrantType = "authorization_code"

	// ClientCredentialsCodeGrant allows machine-to-machine authentication.
	// Used in: Backend service authentication (no user context)
	// Token request includes: client_id, client_secret, scope
	// Returns: access_token (no refresh_token or id_token)
	// Example: Microservice calling another microservice
	ClientCredentialsCodeGrant GrantType = "client_credentials"

	// RefreshTokenCodeGrant exchanges a refresh token for new tokens.
	// Used in: Token refresh flow (get new access token without re-authenticating user)
	// Token request includes: refresh_token, client_id, client_secret
	// Returns: new access_token, id_token, and rotated refresh_token
	RefreshTokenCodeGrant GrantType = "refresh_token"
)

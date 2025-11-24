package auth

import (
	"strings"

	"github.com/jrsteele09/go-auth-server/clients"
)

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

// AuthorizationParameters holds parameters for the OAuth2 authorization request.
// These are typically received as query parameters at the /oauth/authorize endpoint.
type AuthorizationParameters struct {
	// ClientID identifies the application requesting authorization.
	// Flow: All OAuth flows
	// Required: Yes
	// Example: "web-app-client" or "mobile-app-xyz"
	// Validated against: clients.Client.ID in database
	ClientID string

	// ResponseType specifies what the authorization endpoint should return.
	// Flow: Authorization Code Flow
	// Required: Yes
	// Example: "code" (only supported value currently)
	// Standard values: "code", "token" (implicit), "id_token" (implicit)
	ResponseType ResponseType

	// RedirectURI is where the authorization response will be sent.
	// Flow: All OAuth flows
	// Required: Yes
	// Example: "https://myapp.com/callback"
	// Validated against: clients.Client.RedirectURIs whitelist
	// Security: Must exactly match a pre-registered URI to prevent open redirects
	RedirectURI string

	// ResponseMode controls how authorization response is returned (query/fragment/form_post).
	// Flow: Authorization Code Flow (optional parameter)
	// Required: No (defaults to "query" for code flow)
	// Example: "form_post" for better security
	// Used when: Client wants parameters via POST instead of GET
	ResponseMode ResponseModeType

	// Scope specifies the permissions being requested.
	// Flow: All OAuth flows
	// Required: No (but typically includes "openid" for OIDC)
	// Example: "openid profile email api.read"
	// Validated against: clients.Client.Scopes (allowed scopes for this client)
	// Standard scopes: "openid", "profile", "email", "address", "phone", "offline_access"
	Scope string

	// State is an opaque value used by the client to maintain state between request and callback.
	// Flow: All OAuth flows
	// Required: Recommended (CSRF protection)
	// Example: Random string like "abc123xyz789"
	// Security: Client should validate this matches on callback to prevent CSRF attacks
	// Server stores it in session and echoes it back in redirect
	State string

	// CodeChallenge is the PKCE challenge derived from code_verifier.
	// Flow: Authorization Code Flow with PKCE (required for public clients)
	// Required: Yes for public clients, optional for confidential
	// Example: BASE64URL(SHA256(code_verifier))
	// Security: Prevents authorization code interception attacks
	// Length: Typically 43 characters when using S256
	CodeChallenge string

	// CodeChallengeMethod specifies how code_challenge was derived.
	// Flow: Authorization Code Flow with PKCE
	// Required: Yes if code_challenge is provided
	// Example: "S256" or "plain"
	// Default: "plain" if not specified (but S256 strongly recommended)
	CodeChallengeMethod CodeMethodType

	// IdpHint suggests which identity provider to use for authentication.
	// Flow: Federated authentication scenarios
	// Required: No
	// Example: "google", "microsoft", "okta"
	// Used when: Multiple IdPs are configured and you want to skip the selection screen
	IdpHint string

	// Locale specifies the preferred language/locale for the UI.
	// Flow: All OAuth flows
	// Required: No
	// Example: "en-US", "fr-FR", "es-ES"
	// Used for: Showing login page in user's preferred language
	Locale string

	// LoginHint pre-fills the username/email on the login page.
	// Flow: All OAuth flows
	// Required: No
	// Example: "user@example.com"
	// Used for: Improving UX when client knows user's email/username
	// Security: Should not be trusted, only used for UI pre-population
	LoginHint string

	// Nonce is a random value to associate a client session with an ID token.
	// Flow: OpenID Connect (when requesting id_token)
	// Required: Required for implicit flow, recommended for code flow
	// Example: Random string like "n-0S6_WzA2Mj"
	// Security: Prevents replay attacks - server includes it in ID token, client validates
	// Token validation: Client must verify id_token.nonce matches this value
	Nonce string

	// RequestedTenantID specifies which tenant the user should authenticate against.
	// Flow: Multi-tenant scenarios
	// Required: Depends on implementation (may be required if user belongs to multiple tenants)
	// Example: "tenant-123" or "acme-corp"
	// Validated against: User must belong to this tenant, client must be authorized for it
	// Used for: Isolating users/data by organization in multi-tenant systems
	RequestedTenantID string

	// CurrentAccessToken allows session continuation with existing token.
	// Flow: Session extension or silent authentication
	// Required: No
	// Example: Existing JWT access token
	// Used for: Renewing sessions without showing login page, SSO scenarios
	// Security: Must be validated before allowing silent auth
	CurrentAccessToken string
}

// ValidateParametersWithClient validates the Authorization parameters against the client ID
func (p *AuthorizationParameters) ValidateParametersWithClient(client *clients.Client) error {
	// If both client & parameters TenantID is not blank then check they are the same
	if client.TenantID != "" && p.RequestedTenantID != "" && client.TenantID != p.RequestedTenantID {
		return ClientTenantsMismatchErr
	}
	// If the code challenge is not "" then make sure it is at least 256 chars
	if strings.TrimSpace(string(p.CodeChallenge)) != "" && len(p.CodeChallenge) >= 256 {
		return InvalidCodeChallengeErr
	}

	// Check that the code challenge is valid
	if !codeChallengeMethodValid(p.CodeChallenge, CodeMethodType(p.CodeChallengeMethod)) {
		return InvalidCodeChallengeMethodErr
	}

	// Check that the redirect URI is valid for the client
	if !redirectValidForClient(p.RedirectURI, client) {
		return InvalidRedirectUriErr
	}

	// Check that the response mode is valid
	if !responseModeValid(p.ResponseMode) {
		return InvalidResponseModeErr
	}

	// Check that the response type is valid
	if !responseTypeValid(p.ResponseType) {
		return InvalidResponseTypeErr
	}
	return nil
}

func codeChallengeMethodValid(codeChallenge string, challengeMethod CodeMethodType) bool {
	if strings.TrimSpace(codeChallenge) == "" {
		return true
	}
	switch challengeMethod {
	case CodeMethodTypeS256, CodeMethodTypeNone:
		return true
	}
	return false
}

func responseModeValid(responseMode ResponseModeType) bool {
	if strings.TrimSpace(string(responseMode)) == "" {
		return true
	}
	switch responseMode {
	case QueryResponseMode, FormPostResponseMode, FragmentResponseMode:
		return true
	}
	return false
}

func responseTypeValid(responseMode ResponseType) bool {
	if strings.TrimSpace(string(responseMode)) == "" {
		return true
	}
	if responseMode != CodeResponseType {
		return false
	}
	return true
}

func redirectValidForClient(redirectUri string, client *clients.Client) bool {
	for _, uri := range client.RedirectURIs {
		if redirectUri == uri {
			return true
		}
	}
	return false
}

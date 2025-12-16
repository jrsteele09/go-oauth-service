package oauthmodel

import (
	"strings"

	"github.com/jrsteele09/go-auth-server/clients"
)

// AuthorizationParameters holds parameters for the OAuth2 authorization request.
// These are typically received as query parameters at the /oauth/authorize endpoint.
type AuthorizationParameters struct {
	TenantID string

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
		return ErrClientTenantsMismatch
	}
	// If the code challenge is not "" then make sure it is at least 256 chars
	if strings.TrimSpace(string(p.CodeChallenge)) != "" && len(p.CodeChallenge) >= 256 {
		return ErrInvalidCodeChallenge
	}

	// Check that the code challenge is valid
	if !codeChallengeMethodValid(p.CodeChallenge, CodeMethodType(p.CodeChallengeMethod)) {
		return ErrInvalidCodeChallengeMethod
	}

	// Check that the redirect URI is valid for the client
	if !redirectValidForClient(p.RedirectURI, client) {
		return ErrInvalidRedirectUri
	}

	// Check that the response mode is valid
	if !responseModeValid(p.ResponseMode) {
		return ErrInvalidResponseMode
	}

	// Check that the response type is valid
	if !responseTypeValid(p.ResponseType) {
		return ErrInvalidResponseType
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

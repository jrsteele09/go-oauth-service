package auth

import (
	"fmt"
	"strings"

	"github.com/jrsteele09/go-auth-server/clients"
	"github.com/jrsteele09/go-auth-server/oauth2"
	"github.com/jrsteele09/go-auth-server/users"
)

// Validator provides centralized validation logic for OAuth2/OIDC flows.
// This consolidates validation rules that were previously scattered across the codebase.
type Validator struct{}

// NewValidator creates a new Validator instance
func NewValidator() *Validator {
	return &Validator{}
}

// ValidateAuthorizationRequest performs comprehensive validation of authorization request parameters
func (v *Validator) ValidateAuthorizationRequest(
	params *oauth2.AuthorizationParameters,
	client *clients.Client,
	tenant *TenantValidator,
	user *users.User,
) error {
	// Validate client exists
	if client == nil {
		return fmt.Errorf("client not found")
	}

	// Validate parameters against client
	if err := params.ValidateParametersWithClient(client); err != nil {
		return fmt.Errorf("parameter validation failed: %w", err)
	}

	// Enforce PKCE for public clients
	if client.IsPublic() {
		if err := v.ValidatePKCE(params.CodeChallenge, string(params.CodeChallengeMethod), true); err != nil {
			return err
		}
	}

	// Validate scopes
	if err := client.ValidateScopes(params.Scope); err != nil {
		return fmt.Errorf("invalid scope: %w", err)
	}

	// Validate tenant access
	if tenant != nil {
		if err := tenant.ValidateTenantAccess(client, user, params.RequestedTenantID); err != nil {
			return err
		}
	}

	return nil
}

// ValidatePKCE validates PKCE (Proof Key for Code Exchange) parameters
func (v *Validator) ValidatePKCE(codeChallenge, codeChallengeMethod string, required bool) error {
	if codeChallenge == "" && codeChallengeMethod == "" {
		if required {
			return fmt.Errorf("PKCE required: code_challenge and code_challenge_method must be provided")
		}
		return nil
	}

	// If one is provided, both must be provided
	if codeChallenge == "" || codeChallengeMethod == "" {
		return fmt.Errorf("both code_challenge and code_challenge_method must be provided together")
	}

	// Validate code challenge length (should be base64url encoded, typically 43 chars for S256)
	if len(codeChallenge) < 43 || len(codeChallenge) > 128 {
		return fmt.Errorf("code_challenge length must be between 43 and 128 characters")
	}

	// Validate method
	method := oauth2.CodeMethodType(codeChallengeMethod)
	if method != oauth2.CodeMethodTypeS256 && method != oauth2.CodeMethodTypeNone {
		return fmt.Errorf("code_challenge_method must be 'S256' or 'plain'")
	}

	// Recommend S256 for security
	if method == oauth2.CodeMethodTypeNone {
		// Allow but log warning in production
	}

	return nil
}

// ValidateTokenRequest validates token endpoint requests
func (v *Validator) ValidateTokenRequest(
	params oauth2.TokenRequest,
	client *clients.Client,
) error {
	if client == nil {
		return fmt.Errorf("client not found")
	}

	// Validate client credentials
	if err := v.ValidateClientCredentials(params.ClientID, params.ClientSecret, client); err != nil {
		return err
	}

	// Validate based on grant type
	if params.RefreshToken != "" {
		return v.ValidateRefreshTokenGrant(params)
	}

	if params.Code != "" {
		return v.ValidateAuthorizationCodeGrant(params)
	}

	if params.ClientSecret != "" && params.Code == "" {
		return v.ValidateClientCredentialsGrant(params, client)
	}

	return fmt.Errorf("invalid grant type: must provide code or refresh_token")
}

// ValidateClientCredentials validates client ID and secret
func (v *Validator) ValidateClientCredentials(clientID, clientSecret string, client *clients.Client) error {
	if clientID == "" {
		return fmt.Errorf("client_id is required")
	}

	// Public clients don't have secrets
	if client.IsPublic() {
		if clientSecret != "" {
			return fmt.Errorf("public clients must not provide client_secret")
		}
		return nil
	}

	// Confidential clients must provide valid secret
	if clientSecret == "" {
		return fmt.Errorf("client_secret is required for confidential clients")
	}

	if clientSecret != client.Secret {
		return fmt.Errorf("invalid client secret")
	}

	return nil
}

// ValidateAuthorizationCodeGrant validates authorization code grant parameters
func (v *Validator) ValidateAuthorizationCodeGrant(params oauth2.TokenRequest) error {
	if params.Code == "" {
		return fmt.Errorf("authorization code is required")
	}

	// Code verifier is required if PKCE was used (we'll check this against session later)
	// Length validation: RFC 7636 specifies 43-128 characters
	if params.CodeVerifier != "" && (len(params.CodeVerifier) < 43 || len(params.CodeVerifier) > 128) {
		return fmt.Errorf("code_verifier must be between 43 and 128 characters")
	}

	return nil
}

// ValidateRefreshTokenGrant validates refresh token grant parameters
func (v *Validator) ValidateRefreshTokenGrant(params oauth2.TokenRequest) error {
	if params.RefreshToken == "" {
		return fmt.Errorf("refresh_token is required")
	}

	if len(params.RefreshToken) < 10 {
		return fmt.Errorf("invalid refresh_token format")
	}

	return nil
}

// ValidateClientCredentialsGrant validates client credentials grant
func (v *Validator) ValidateClientCredentialsGrant(params oauth2.TokenRequest, client *clients.Client) error {
	// Must be confidential client
	if client.IsPublic() {
		return fmt.Errorf("client credentials grant not allowed for public clients")
	}

	// Secret already validated in ValidateClientCredentials
	return nil
}

// ValidateAccessToken validates access token format and presence
func (v *Validator) ValidateAccessToken(token string) error {
	token = strings.TrimSpace(token)
	if token == "" {
		return fmt.Errorf("access token is required")
	}

	// Basic format check - should be a JWT (3 parts separated by dots)
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return fmt.Errorf("invalid token format: must be a valid JWT")
	}

	// Each part should have content
	for i, part := range parts {
		if len(part) == 0 {
			return fmt.Errorf("invalid token format: part %d is empty", i+1)
		}
	}

	return nil
}

// ValidateUserCredentials validates login credentials
func (v *Validator) ValidateUserCredentials(email, password string) error {
	email = strings.TrimSpace(email)
	if email == "" {
		return fmt.Errorf("email is required")
	}

	// Basic email format validation
	if !strings.Contains(email, "@") || !strings.Contains(email, ".") {
		return fmt.Errorf("invalid email format")
	}

	if password == "" {
		return fmt.Errorf("password is required")
	}

	if len(password) < 1 {
		return fmt.Errorf("password cannot be empty")
	}

	return nil
}

// ValidateUserState validates user account state (blocked, verified, etc.)
func (v *Validator) ValidateUserState(user *users.User) error {
	if user == nil {
		return fmt.Errorf("user not found")
	}

	if user.Blocked {
		return fmt.Errorf("user account is blocked")
	}

	if !user.Verified {
		return fmt.Errorf("user account is not verified")
	}

	return nil
}

// TenantValidator handles tenant-related validation
type TenantValidator struct {
	tenantID string
}

// NewTenantValidator creates a validator for a specific tenant
func NewTenantValidator(tenantID string) *TenantValidator {
	return &TenantValidator{tenantID: tenantID}
}

// ValidateTenantAccess checks if user and client can access the requested tenant
func (tv *TenantValidator) ValidateTenantAccess(client *clients.Client, user *users.User, requestedTenantID string) error {
	// Determine which tenant to validate against
	tenantID := tv.tenantID
	if requestedTenantID != "" {
		tenantID = requestedTenantID
	}

	if tenantID == "" {
		return nil // No tenant restrictions
	}

	// Validate client belongs to tenant
	if client.TenantID != "" && client.TenantID != tenantID {
		return fmt.Errorf("client not authorized for tenant")
	}

	// Validate user belongs to tenant (if user is present)
	if user != nil && !user.HasTenant(tenantID) {
		return fmt.Errorf("user not authorized for tenant")
	}

	return nil
}

// ValidateScope validates individual scope strings
func ValidateScope(scope string) error {
	scope = strings.TrimSpace(scope)
	if scope == "" {
		return nil // Empty scope is valid
	}

	// Check for invalid characters
	if strings.ContainsAny(scope, "\n\r\t") {
		return fmt.Errorf("scope contains invalid characters")
	}

	// Scopes should not have leading/trailing spaces in individual tokens
	scopes := strings.Split(scope, " ")
	for _, s := range scopes {
		if s != strings.TrimSpace(s) {
			return fmt.Errorf("scope tokens must not have leading/trailing spaces")
		}
	}

	return nil
}

// ValidateRedirectURI validates redirect URI format
func ValidateRedirectURI(uri string) error {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return fmt.Errorf("redirect_uri is required")
	}

	// Must start with http:// or https://
	if !strings.HasPrefix(uri, "http://") && !strings.HasPrefix(uri, "https://") {
		return fmt.Errorf("redirect_uri must use http or https scheme")
	}

	// Should not contain fragments
	if strings.Contains(uri, "#") {
		return fmt.Errorf("redirect_uri must not contain fragments")
	}

	return nil
}

// ValidateState validates OAuth state parameter
func ValidateState(state string) error {
	// State is optional, but if provided should meet minimum requirements
	if state == "" {
		return nil
	}

	// Should be reasonably long for CSRF protection
	if len(state) < 8 {
		return fmt.Errorf("state parameter should be at least 8 characters for security")
	}

	// Should not contain whitespace
	if strings.TrimSpace(state) != state {
		return fmt.Errorf("state parameter must not contain leading/trailing whitespace")
	}

	return nil
}

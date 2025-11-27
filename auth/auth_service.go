package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jrsteele09/go-auth-server/clients"
	"github.com/jrsteele09/go-auth-server/internal/utils"
	"github.com/jrsteele09/go-auth-server/oauth2"
	"github.com/jrsteele09/go-auth-server/sessions"
	"github.com/jrsteele09/go-auth-server/tenants"
	"github.com/jrsteele09/go-auth-server/token"
	"github.com/jrsteele09/go-auth-server/users"
)

// NowTimeFunc is a package-level variable that returns the current time.
// It can be overridden in tests to control time-dependent behavior.
var NowTimeFunc = time.Now

// MFARedirectFunc defines a function type for handling redirection to MFA verification.
// This is specific to the auth layer and handles multi-factor authentication flows.
//
// Parameters:
//   - redirectURI: The URI where the user should be redirected for MFA verification
//   - mfaType: The type of MFA being used (e.g., TOTP, SMS)
//   - state: The state parameter to maintain across the MFA flow
type MFARedirectFunc func(redirectURI string, mfaType users.MFAuthType, state string)

// AuthorizationRedirectFunc defines a function type for handling the redirection after the OAuth2
// authorization process. Depending on the OAuth2 flow and the provided `responseMode`, this function
// will determine the format and content of the redirection URL, including any tokens, codes, or errors
// that should be appended.
//
// Parameters:
//   - redirectURI: The original URI provided by the client where the user-agent will be redirected after
//     the authorization process.
//   - responseMode: The method that should be used for returning parameters from the authorization endpoint.
//     This can dictate if the tokens or codes are returned in the query string, fragment, or via a form post.
//   - authorizationCode: If the OAuth2 flow is "authorization_code", this will be the generated code.
//     For other flows, this will be an empty string.
//   - state: The CSRF token or other state value that was originally passed in the authorization request.
//     This should be echoed back in the redirect to help clients prevent certain types of attacks.
type AuthorizationRedirectFunc func(redirectURI string, responseMode oauth2.ResponseModeType, authorizationCode string, state string)

// Possible OAuth2 response types, response modes, challenge methods, and grant types.
const (
	codeGenerationLength = 32
	authCodeTimeout      = 15 * time.Minute
)

// Repos holds all repository dependencies for the AuthorizationService
type Repos struct {
	Users    users.UserRepo // Repository for user data
	Sessions sessions.Repo  // Repository for session data
	Clients  clients.Repo   // Repository for OAuth2 client data
	Tenants  tenants.Repo   // Repository for tenant data
}

// AuthorizationService provides methods for OAuth2 authorization and token requests.
type AuthorizationService struct {
	repos        Repos          // All repository dependencies
	tokenManager *token.Manager // Create and handle token generation
}

// NewAuthorizationService initializes a new AuthorizationService with required dependencies.
func NewAuthorizationService(
	repos Repos,
	tokenCreator *token.Manager,
) (*AuthorizationService, error) {
	// Validate required parameters
	if repos.Users == nil {
		return nil, fmt.Errorf("[NewAuthorizationService] Users repo is required")
	}
	if repos.Sessions == nil {
		return nil, fmt.Errorf("[NewAuthorizationService] Sessions repo is required")
	}
	if repos.Clients == nil {
		return nil, fmt.Errorf("[NewAuthorizationService] Clients repo is required")
	}
	if repos.Tenants == nil {
		return nil, fmt.Errorf("[NewAuthorizationService] Tenants repo is required")
	}
	if tokenCreator == nil {
		return nil, fmt.Errorf("[NewAuthorizationService] tokenCreator is required")
	}

	authService := &AuthorizationService{
		repos:        repos,
		tokenManager: tokenCreator,
	}

	return authService, nil
}

// Authorize initiates the OAuth 2.0 authorization process.
// login is a function to execute if the user needs to authenticate.
// redirect is a function to handle the redirection after the authorization process.
func (as *AuthorizationService) Authorize(parameters *oauth2.AuthorizationParameters, loginRedirect func(sessionID string), oauthRedirect AuthorizationRedirectFunc) error {
	// Get the Client
	client, err := as.repos.Clients.Get(parameters.ClientID)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrInvalidClientID.Error(), err)
	}

	// Validate the essential parameters with the client
	if err := parameters.ValidateParametersWithClient(client); err != nil {
		return fmt.Errorf("[Authorize] failed parameter validation: %w", err)
	}

	// Enforce PKCE for public clients
	if client.IsPublic() && (parameters.CodeChallenge == "" || parameters.CodeChallengeMethod == "") {
		return fmt.Errorf("[Authorize] PKCE required for public clients")
	}

	// Validate scopes
	if err := client.ValidateScopes(parameters.Scope); err != nil {
		return fmt.Errorf("[Authorize] invalid scope: %w", err)
	}

	// Set the requested tenant
	tenantID := client.TenantID

	if parameters.RequestedTenantID != "" {
		tenantID = parameters.RequestedTenantID
	}

	// Check The Tenant Exists
	_, err = as.repos.Tenants.Get(tenantID)
	if err != nil {
		return fmt.Errorf("%s: %w", ErrInvalidTenant.Error(), err)
	}

	// Introspect the token and pull out any active, non blocked, user
	user, err := as.tokenUser(parameters.CurrentAccessToken)
	if err != nil {
		return fmt.Errorf("[Authorize] introspectToken: %w", err)
	}

	if user != nil && !user.HasTenant(tenantID) {
		return fmt.Errorf("[Authorize] User not in Tenant")
	}

	// New session ID
	sessionID := uuid.New().String()

	// Hash the state parameter for CSRF validation
	var stateHash string
	if parameters.State != "" {
		hash := sha256.Sum256([]byte(parameters.State))
		stateHash = base64.URLEncoding.EncodeToString(hash[:])
	}

	if err := as.repos.Sessions.Upsert(sessionID, &sessions.SessionData{
		TenantID:            tenantID,
		AuthorizationParams: parameters,
		Timestamp:           NowTimeFunc(),
		StateHash:           stateHash,
	}); err != nil {
		return fmt.Errorf("[Authorize] failed to create session: %w", err)
	}

	// Already have a logged in user, create new code
	if utils.Value(user).LoggedIn {
		if err := as.generateAuthorizationCodeAndRedirect(sessionID, oauthRedirect); err != nil {
			return fmt.Errorf("[Authorize] failed generating auth code and redirecting: %w", err)
		}
		return nil
	}

	// Redirect to login
	loginRedirect(sessionID)
	return nil
}

// Login checks the credentials and triggers the MFA challenge if needed.
func (as *AuthorizationService) Login(sessionID, email, password string, oauthRedirect AuthorizationRedirectFunc, mfaRedirect MFARedirectFunc) error {
	// Get the session
	sessionData, err := as.repos.Sessions.Get(sessionID)
	if err != nil {
		return fmt.Errorf("[AuthorizationService.Login] sessionRepo.Get: %w", err)
	}

	// Get User
	user, err := as.repos.Users.GetByEmail(email)
	if err != nil {
		return fmt.Errorf("[AuthorizationService.Login] GetByEmail: %w", err)
	}

	if !user.HasTenant(sessionData.TenantID) {
		return fmt.Errorf("[AuthorizationService.Login] incorrect Tenant")
	}

	// Check Password
	if !users.CheckPasswordHash(password, user.PasswordHash) {
		return ErrUserPasswordsDontMatch
	}

	// Check MFA Auth and redirect if configured
	if user.MFAAuth() {
		mfaRedirect("", user.MFType, sessionData.AuthorizationParams.State)
		return nil
	}
	as.repos.Sessions.UpdateUser(sessionID, email)
	as.generateAuthorizationCodeAndRedirect(sessionID, oauthRedirect)
	return nil
}

func (as *AuthorizationService) Logout(email, refreshToken string) error {
	as.tokenManager.InvalidateRefreshToken(refreshToken)
	err := as.repos.Users.SetLoggedIn(email, false)
	if err != nil {
		return fmt.Errorf("[AuthorizationService.Login] userRepo.SetLoggedIn: %w", err)
	}
	return nil
}

// MFAAuth handles the Multi-Factor Authentication process.
func (as *AuthorizationService) MFAAuth(sessionID, mfaCode string, redirect AuthorizationRedirectFunc) error {
	return nil
}

// Token handles the OAuth 2.0 token request.
func (as *AuthorizationService) Token(parameters oauth2.TokenRequest) (*oauth2.TokenResponse, error) {
	// Get the client data
	client, err := as.repos.Clients.Get(parameters.ClientID)
	if err != nil {
		return nil, fmt.Errorf("[AuthorizationService.Token] invalid client ID: %w", err)
	}
	// Client ID and Secret
	if parameters.ClientSecret != "" && parameters.ClientSecret != client.Secret {
		return nil, fmt.Errorf("[AuthorizationService.Token] client secret incorrect")
	}

	// Refresh token grant - handled by token creator
	if parameters.RefreshToken != "" {
		return as.tokenManager.GenerateTokenResponse(parameters, token.TokenSpecifics{})
	}

	// Client credentials grant
	if parameters.ClientSecret == client.Secret && parameters.Code == "" {
		return as.tokenManager.GenerateTokenResponse(parameters, token.TokenSpecifics{
			TenantID: client.TenantID,
		})
	}

	// Auth Code
	sessionData, err := as.repos.Sessions.GetSessionFromAuthCode(parameters.Code)
	if err != nil {
		return nil, fmt.Errorf("[AuthorizationService.Token] Auth Code invalid")
	}
	defer func() {
		_ = as.repos.Sessions.Delete(sessionData.ID)
	}()
	if time.Since(sessionData.Timestamp) > authCodeTimeout {
		return nil, fmt.Errorf("[AuthorizationService.Token] Auth Code timeout")
	}

	// Code Verifier challenge
	if !checkCodeChallenge(sessionData.AuthorizationParams.CodeChallenge, parameters.CodeVerifier, sessionData.AuthorizationParams.CodeChallengeMethod) {
		return nil, fmt.Errorf("[AuthorizationService.Token] code challenge failed")
	}

	// Generate Token Response
	tr, err := as.tokenManager.GenerateTokenResponse(parameters, token.TokenSpecifics{
		Scope:     sessionData.AuthorizationParams.Scope,
		TenantID:  sessionData.TenantID,
		UserEmail: sessionData.UserEmail,
		Nonce:     sessionData.AuthorizationParams.Nonce,
	})

	if err != nil {
		return nil, fmt.Errorf("[AuthorizationService.Token] tokenCreator.GenerateTokenResponse: %w", err)
	}

	// Set the User as Logged In
	if err := as.repos.Users.SetLoggedIn(sessionData.UserEmail, true); err != nil {
		return nil, fmt.Errorf("[AuthorizationService.Token] as.repos.Users.SetLoggedIn: %w", err)
	}

	// Return the token response
	return tr, nil
}

func (as *AuthorizationService) generateAuthorizationCodeAndRedirect(sessionID string, redirect AuthorizationRedirectFunc) error {
	sessionData, err := as.repos.Sessions.Get(sessionID)
	if err != nil {
		return fmt.Errorf("generateAuthorizationCodeAndRedirect sessionID: %w", err)
	}

	bytes := make([]byte, codeGenerationLength)
	if _, err := rand.Read(bytes); err != nil {
		return fmt.Errorf("generateAuthorizationCodeAndRedirect rand.Read: %w", err)
	}
	code := base64.URLEncoding.EncodeToString(bytes)
	if err := as.repos.Sessions.AssignCodeToSessionID(sessionID, code); err != nil {
		return fmt.Errorf("AssignCodeToSessionID: %w", err)
	}
	redirect(sessionData.AuthorizationParams.RedirectURI, sessionData.AuthorizationParams.ResponseMode, code, sessionData.AuthorizationParams.State)
	return nil
}

func checkCodeChallenge(storedChallenge, verifier string, method oauth2.CodeMethodType) bool {
	if storedChallenge == "" && verifier == "" { // No PKCE code challenge
		return true
	}
	switch method {
	case oauth2.CodeMethodTypeS256:
		hash := sha256.Sum256([]byte(verifier))
		return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(hash[:]) == storedChallenge
	case oauth2.CodeMethodTypeNone:
		return storedChallenge == verifier
	}
	return false
}

func (as *AuthorizationService) tokenUser(rawToken string) (*users.User, error) {
	if strings.TrimSpace(rawToken) == "" {
		return nil, nil
	}
	if introspectionToken, err := as.tokenManager.Introspection(rawToken); err != nil {
		return nil, nil
	} else if introspectionToken.Active {
		if utils.Value(introspectionToken.Sub) == "" {
			return nil, nil
		}
		user, err := as.repos.Users.GetByID(utils.Value(introspectionToken.Sub))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", ErrUserNotFound.Error(), err)
		}
		if user.Blocked {
			return nil, fmt.Errorf("%s", ErrUserBlocked.Error())
		}
		if !user.Verified {
			return nil, fmt.Errorf("%s", ErrUserUnverified.Error())
		}
		return user, nil
	}
	return nil, nil
}

// IntrospectToken validates and returns metadata about an access token
// This method should be called by resource servers to validate tokens
func (as *AuthorizationService) IntrospectToken(rawToken, clientID, clientSecret string) (*token.TokenIntrospection, error) {
	// Validate client credentials first
	client, err := as.repos.Clients.Get(clientID)
	if err != nil || client.Secret != clientSecret {
		return &token.TokenIntrospection{Active: false}, nil
	}

	// Return introspection result
	return as.tokenManager.Introspection(rawToken)
}

// RevokeToken revokes an access or refresh token
func (as *AuthorizationService) RevokeToken(rawToken, tokenTypeHint, clientID, clientSecret string) error {
	// Validate client credentials
	client, err := as.repos.Clients.Get(clientID)
	if err != nil || client.Secret != clientSecret {
		return fmt.Errorf("invalid client credentials")
	}

	// Determine token type
	if tokenTypeHint == "refresh_token" {
		// Revoke as refresh token
		as.tokenManager.InvalidateRefreshToken(rawToken)
		return nil
	}

	// Revoke as access token (default)
	return as.tokenManager.RevokeAccessToken(rawToken)
}

// UserInfo returns user information based on an access token
func (as *AuthorizationService) UserInfo(rawToken string) (map[string]interface{}, error) {
	// Introspect the token
	introspection, err := as.tokenManager.Introspection(rawToken)
	if err != nil {
		return nil, fmt.Errorf("failed to introspect token: %w", err)
	}

	if !introspection.Active {
		return nil, fmt.Errorf("token is not active")
	}

	// Get user information
	if introspection.Sub == nil || *introspection.Sub == "" {
		return nil, fmt.Errorf("token does not contain user information")
	}

	user, err := as.repos.Users.GetByID(*introspection.Sub)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	if user.Blocked {
		return nil, fmt.Errorf("user is blocked")
	}

	if !user.Verified {
		return nil, fmt.Errorf("user is not verified")
	}

	// Return standard OIDC UserInfo claims
	userInfo := map[string]interface{}{
		"sub":                user.ID,
		"email":              user.Email,
		"email_verified":     user.Verified,
		"name":               user.FirstName + " " + user.LastName,
		"given_name":         user.FirstName,
		"family_name":        user.LastName,
		"preferred_username": user.Username,
	}

	return userInfo, nil
}

// CleanupExpiredSessions removes sessions that have exceeded the timeout
func (as *AuthorizationService) CleanupExpiredSessions() error {
	// Get all sessions and remove expired ones
	cutoff := NowTimeFunc().Add(-authCodeTimeout)

	// This is a placeholder - actual implementation depends on SessionRepo
	// You may want to add a CleanupExpired method to SessionRepo interface
	_ = cutoff
	return nil
}

// CleanupRevokedTokens removes expired tokens from the revocation cache
func (as *AuthorizationService) CleanupRevokedTokens() {
	as.tokenManager.CleanupRevokedTokens()
}

// GetJWKS returns the JSON Web Key Set for public key distribution
// If tenantID is provided, returns tenant-specific keys; otherwise returns default keys
func (as *AuthorizationService) GetJWKS(tenantID string) (*token.JWKS, error) {
	return as.tokenManager.GetJWKS(tenantID)
}

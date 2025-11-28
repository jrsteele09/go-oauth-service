package auth_test

import (
	"testing"
	"time"

	"github.com/jrsteele09/go-auth-server/auth"
	"github.com/jrsteele09/go-auth-server/auth/sessions"
	fakesessionrepo "github.com/jrsteele09/go-auth-server/auth/sessions/repofakes"
	"github.com/jrsteele09/go-auth-server/clients"
	fakeclientrepo "github.com/jrsteele09/go-auth-server/clients/fakerepo"
	"github.com/jrsteele09/go-auth-server/internal/config"
	"github.com/jrsteele09/go-auth-server/internal/utils"
	"github.com/jrsteele09/go-auth-server/oauth2"
	"github.com/jrsteele09/go-auth-server/tenants"
	tenantrepofakes "github.com/jrsteele09/go-auth-server/tenants/repofakes"
	"github.com/jrsteele09/go-auth-server/token"
	"github.com/jrsteele09/go-auth-server/token/keys"
	refreshrepofake "github.com/jrsteele09/go-auth-server/token/refresh/repofake"
	"github.com/jrsteele09/go-auth-server/users"
	fakeuserrepo "github.com/jrsteele09/go-auth-server/users/repofake"
	"github.com/stretchr/testify/require"
)

const (
	issuer            = "com.testissuer"
	audience          = "api"
	testClientID      = "test-client-1"
	testClientSecret  = "test-secret-1"
	testTenantID      = "tenant-1"
	testUserID        = "user-1"
	testUserEmail     = "john.doe@example.com"
	testUserPassword  = "password123"
	testRedirectURI   = "http://localhost:3000/callback"
	testState         = "random-state-value"
	testCodeChallenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	testCodeVerifier  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
)

// testFixture holds all test dependencies
type testFixture struct {
	userRepo         users.UserRepo
	sessionRepo      sessions.Repo
	clientRepo       clients.Repo
	tenantsRepo      tenants.Repo
	refreshTokenRepo *refreshrepofake.FakeRefreshTokenRepo
	tokenCreator     *token.Manager
	service          *auth.AuthorizationService
}

// testUser represents a test user with common fields
type testUser struct {
	ID          string
	Email       string
	Username    string
	Password    string
	FirstName   string
	LastName    string
	SystemRoles []users.RoleType
	TenantRoles map[string][]users.RoleType // tenantID -> roles
	TenantIDs   []string
	Verified    bool
	Blocked     bool
}

// testClient represents a test OAuth client
type testClient struct {
	ID           string
	Secret       string
	Description  string
	RedirectURIs []string
	Type         clients.ClientType
	Scopes       []string
	TenantID     string
}

// setupTestFixture creates a new test fixture with all dependencies
func setupTestFixture(t *testing.T) *testFixture {
	t.Helper()

	ur := fakeuserrepo.NewFakeUserRepo()
	sr := fakesessionrepo.NewFakeSessionRepo()
	cr := fakeclientrepo.NewFakeClientRepo()
	tr := tenantrepofakes.NewFakeTenantRepo()
	rtr := refreshrepofake.NewFakeRefreshTokenRepo()

	cfg := config.New()

	repos := auth.Repos{
		Users:         ur,
		Sessions:      sr,
		Clients:       cr,
		Tenants:       tr,
		RefreshTokens: rtr,
	}

	authService, err := auth.NewAuthorizationService(repos, cfg)
	require.NoError(t, err)

	// Create token manager for tests that need direct access
	tc := token.NewManager(rtr, ur, tr, cfg)

	return &testFixture{
		userRepo:         ur,
		sessionRepo:      sr,
		clientRepo:       cr,
		tenantsRepo:      tr,
		tokenCreator:     tc,
		refreshTokenRepo: rtr.(*refreshrepofake.FakeRefreshTokenRepo),
		service:          authService,
	}
}

// createTestUser creates and stores a test user
func (f *testFixture) createTestUser(t *testing.T, user testUser) {
	t.Helper()

	passwordHash, err := users.HashPassword(user.Password)
	require.NoError(t, err)

	// Build tenant memberships from TenantRoles map
	tenants := make([]users.TenantMembership, 0, len(user.TenantIDs))
	for _, tenantID := range user.TenantIDs {
		roles := user.TenantRoles[tenantID]
		if roles == nil {
			roles = []users.RoleType{} // Default to empty roles if not specified
		}
		tenants = append(tenants, users.TenantMembership{
			TenantID: tenantID,
			Roles:    roles,
			JoinedAt: time.Now(),
		})
	}

	err = f.userRepo.Upsert(&users.User{
		ID:           user.ID,
		Email:        user.Email,
		Username:     user.Username,
		PasswordHash: passwordHash,
		FirstName:    user.FirstName,
		LastName:     user.LastName,
		SystemRoles:  user.SystemRoles,
		Tenants:      tenants,
		TenantIDs:    user.TenantIDs,
		Verified:     user.Verified,
		Blocked:      user.Blocked,
		LoggedIn:     false,
	})
	require.NoError(t, err)
}

// createTestClient creates and stores a test OAuth client
func (f *testFixture) createTestClient(t *testing.T, client testClient) {
	t.Helper()

	err := f.clientRepo.Upsert(&clients.Client{
		ID:           client.ID,
		Secret:       client.Secret,
		Description:  client.Description,
		RedirectURIs: client.RedirectURIs,
		Type:         client.Type,
		Scopes:       client.Scopes,
		TenantID:     client.TenantID,
	})
	require.NoError(t, err)
}

// createTestTenant creates and stores a test tenant with key material
func (f *testFixture) createTestTenant(t *testing.T, id, name, domain string) {
	t.Helper()

	tenant := &tenants.Tenant{
		ID:     id,
		Name:   name,
		Domain: domain,
		Config: tenants.TenantConfig{
			Issuer:             issuer,
			Audience:           audience,
			AccessTokenExpiry:  15 * time.Minute,
			IDTokenExpiry:      time.Hour,
			RefreshTokenExpiry: 7 * 24 * time.Hour,
		},
		Keys: tenants.TenantKeys{
			KeyID: id + "-key",
		},
	}

	// Generate signing key material for the tenant
	err := keys.GenerateKeysForTenant(tenant)
	require.NoError(t, err)

	err = f.tenantsRepo.Upsert(tenant)
	require.NoError(t, err)
}

// defaultTestUser returns a default test user
func defaultTestUser() testUser {
	return testUser{
		ID:          testUserID,
		Email:       testUserEmail,
		Username:    "johndoe",
		Password:    testUserPassword,
		FirstName:   "John",
		LastName:    "Doe",
		SystemRoles: []users.RoleType{},
		TenantRoles: map[string][]users.RoleType{
			testTenantID: {users.RoleTenantUser},
		},
		TenantIDs: []string{testTenantID},
		Verified:  true,
		Blocked:   false,
	}
}

// defaultTestClient returns a default confidential client
func defaultTestClient() testClient {
	return testClient{
		ID:           testClientID,
		Secret:       testClientSecret,
		Description:  "Test Client",
		RedirectURIs: []string{testRedirectURI},
		Type:         clients.ClientTypeConfidential,
		Scopes:       []string{"openid", "profile", "email"},
		TenantID:     testTenantID,
	}
}

// publicTestClient returns a public client (requires PKCE)
func publicTestClient() testClient {
	client := defaultTestClient()
	client.ID = "public-client-1"
	client.Secret = ""
	client.Type = clients.ClientTypePublic
	return client
}

// setupStandardTestEnvironment creates the standard test environment with default client, tenant, and user
func (f *testFixture) setupStandardTestEnvironment(t *testing.T) {
	t.Helper()
	f.createTestClient(t, defaultTestClient())
	f.createTestTenant(t, testTenantID, "Test Tenant", "https://tenant.example.com")
	f.createTestUser(t, defaultTestUser())
}

// setupMinimalTestEnvironment creates just client and tenant (no user)
func (f *testFixture) setupMinimalTestEnvironment(t *testing.T) {
	t.Helper()
	f.createTestClient(t, defaultTestClient())
	f.createTestTenant(t, testTenantID, "Test Tenant", "https://tenant.example.com")
}

// TestAuthorize_CreatesSession tests that Authorize creates a session and triggers login
func TestAuthorize_CreatesSession(t *testing.T) {
	f := setupTestFixture(t)
	f.createTestClient(t, defaultTestClient())
	f.createTestTenant(t, testTenantID, "Test Tenant", "https://tenant.example.com")

	var capturedSessionID string
	loginFunc := func(sessionID string) {
		capturedSessionID = sessionID
	}

	params := &oauth2.AuthorizationParameters{
		ClientID:     testClientID,
		ResponseType: "code",
		RedirectURI:  testRedirectURI,
		ResponseMode: oauth2.QueryResponseMode,
		Scope:        "openid email",
		State:        testState,
	}

	err := f.service.Authorize(params, loginFunc, nil)

	require.NoError(t, err)
	require.NotEmpty(t, capturedSessionID, "Should create a session and call login function")
}

// TestAuthorize_InvalidClient tests authorization with invalid client
func TestAuthorize_InvalidClient(t *testing.T) {
	f := setupTestFixture(t)

	params := &oauth2.AuthorizationParameters{
		ClientID:     "non-existent-client",
		ResponseType: "code",
		RedirectURI:  testRedirectURI,
	}

	err := f.service.Authorize(params, nil, nil)

	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid client")
}

// TestAuthorize_InvalidTenant tests authorization with invalid tenant
func TestAuthorize_InvalidTenant(t *testing.T) {
	f := setupTestFixture(t)
	client := defaultTestClient()
	client.TenantID = "non-existent-tenant"
	f.createTestClient(t, client)

	params := &oauth2.AuthorizationParameters{
		ClientID:     testClientID,
		ResponseType: "code",
		RedirectURI:  testRedirectURI,
	}

	err := f.service.Authorize(params, nil, nil)

	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid tenant")
}

// TestAuthorize_PublicClientRequiresPKCE tests that public clients must provide PKCE
func TestAuthorize_PublicClientRequiresPKCE(t *testing.T) {
	f := setupTestFixture(t)
	f.createTestClient(t, publicTestClient())
	f.createTestTenant(t, testTenantID, "Test Tenant", "https://tenant.example.com")

	params := &oauth2.AuthorizationParameters{
		ClientID:     "public-client-1",
		ResponseType: "code",
		RedirectURI:  testRedirectURI,
		Scope:        "openid",
		// Missing CodeChallenge - should fail
	}

	err := f.service.Authorize(params, nil, nil)

	require.Error(t, err)
	require.Contains(t, err.Error(), "PKCE required")
}

// TestAuthorize_InvalidScope tests authorization with invalid scope
func TestAuthorize_InvalidScope(t *testing.T) {
	f := setupTestFixture(t)
	f.createTestClient(t, defaultTestClient())
	f.createTestTenant(t, testTenantID, "Test Tenant", "https://tenant.example.com")

	params := &oauth2.AuthorizationParameters{
		ClientID:     testClientID,
		ResponseType: "code",
		RedirectURI:  testRedirectURI,
		Scope:        "invalid-scope", // Not in client's allowed scopes
	}

	err := f.service.Authorize(params, nil, nil)

	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid scope")
}

// TestAuthorize_InvalidRedirectURI tests authorization with wrong redirect URI
func TestAuthorize_InvalidRedirectURI(t *testing.T) {
	f := setupTestFixture(t)
	f.createTestClient(t, defaultTestClient())
	f.createTestTenant(t, testTenantID, "Test Tenant", "https://tenant.example.com")

	// Wrong redirect URI
	params := &oauth2.AuthorizationParameters{
		ClientID:     testClientID,
		ResponseType: "code",
		RedirectURI:  "https://wrong-redirect.com/callback",
		Scope:        "openid",
	}

	loginCB := func(sessionID string) {}
	oauthCB := func(redirectURI string, responseMode oauth2.ResponseModeType, code, state string) {}
	err := f.service.Authorize(params, loginCB, oauthCB)

	require.Error(t, err)
	require.Contains(t, err.Error(), "parameter validation")
}

// TestLogin_Success tests successful login
func TestLogin_Success(t *testing.T) {
	f := setupTestFixture(t)
	f.setupStandardTestEnvironment(t)

	// First authorize to create session
	var sessionID string
	params := &oauth2.AuthorizationParameters{
		ClientID:     testClientID,
		ResponseType: "code",
		RedirectURI:  testRedirectURI,
		Scope:        "openid email",
		State:        testState,
	}

	err := f.service.Authorize(params, func(sid string) { sessionID = sid }, nil)
	require.NoError(t, err)

	// Now login
	var capturedCode string
	var capturedState string
	redirectFunc := func(uri string, mode oauth2.ResponseModeType, code, state string) {
		capturedCode = code
		capturedState = state
	}

	err = f.service.Login(sessionID, testUserEmail, testUserPassword, redirectFunc, nil)

	require.NoError(t, err)
	require.NotEmpty(t, capturedCode, "Should generate authorization code")
	require.Equal(t, testState, capturedState, "Should return original state")
}

// TestLogin_InvalidPassword tests login with wrong password
func TestLogin_InvalidPassword(t *testing.T) {
	f := setupTestFixture(t)
	f.setupStandardTestEnvironment(t)

	var sessionID string
	params := &oauth2.AuthorizationParameters{
		ClientID:     testClientID,
		ResponseType: "code",
		RedirectURI:  testRedirectURI,
		Scope:        "openid",
	}

	err := f.service.Authorize(params, func(sid string) { sessionID = sid }, nil)
	require.NoError(t, err)

	err = f.service.Login(sessionID, testUserEmail, "wrong-password", nil, nil)

	require.Error(t, err)
	require.Contains(t, err.Error(), "passwords")
}

// TestLogin_WrongTenant tests login when user is not in the requested tenant
func TestLogin_WrongTenant(t *testing.T) {
	f := setupTestFixture(t)
	f.setupMinimalTestEnvironment(t)

	user := defaultTestUser()
	user.TenantIDs = []string{"different-tenant"} // Not in test tenant
	f.createTestUser(t, user)

	var sessionID string
	params := &oauth2.AuthorizationParameters{
		ClientID:     testClientID,
		ResponseType: "code",
		RedirectURI:  testRedirectURI,
		Scope:        "openid",
	}

	err := f.service.Authorize(params, func(sid string) { sessionID = sid }, nil)
	require.NoError(t, err)

	redirectFunc := func(uri string, mode oauth2.ResponseModeType, code, state string) {}
	err = f.service.Login(sessionID, testUserEmail, testUserPassword, redirectFunc, nil)

	require.Error(t, err)
	require.Contains(t, err.Error(), "incorrect Tenant")
}

// TestLogin_InvalidSession tests login with non-existent session
func TestLogin_InvalidSession(t *testing.T) {
	f := setupTestFixture(t)

	redirectFunc := func(redirectURI string, responseMode oauth2.ResponseModeType, code, state string) {}
	err := f.service.Login("invalid-session-id", testUserEmail, testUserPassword, redirectFunc, nil)

	require.Error(t, err)
	require.Contains(t, err.Error(), "sessionRepo.Get")
}

// TestLogin_UserNotFound tests login with non-existent user
func TestLogin_UserNotFound(t *testing.T) {
	f := setupTestFixture(t)
	f.setupMinimalTestEnvironment(t)

	// Start authorization to create session
	var sessionID string
	params := &oauth2.AuthorizationParameters{
		ClientID:     testClientID,
		ResponseType: oauth2.CodeResponseType,
		RedirectURI:  testRedirectURI,
		Scope:        "openid",
	}
	err := f.service.Authorize(params, func(sid string) { sessionID = sid }, nil)
	require.NoError(t, err)
	require.NotEmpty(t, sessionID)

	// Try to login with non-existent user
	redirectFunc := func(redirectURI string, responseMode oauth2.ResponseModeType, code, state string) {}
	err = f.service.Login(sessionID, "nonexistent@example.com", "password", redirectFunc, nil)

	require.Error(t, err)
	require.Contains(t, err.Error(), "GetByEmail")
}

// TestToken_ExchangeCodeSuccess tests successful token exchange
func TestToken_ExchangeCodeSuccess(t *testing.T) {
	f := setupTestFixture(t)
	f.setupStandardTestEnvironment(t)

	// Complete authorization flow
	authCode := performAuthorizationFlow(t, f, testUserEmail, testUserPassword)

	// Exchange code for tokens
	tokenParams := oauth2.TokenRequest{
		ClientID: testClientID,
		Code:     authCode,
	}

	tokenResponse, err := f.service.Token(tokenParams)

	require.NoError(t, err)
	require.NotNil(t, tokenResponse.AccessToken)
	require.NotNil(t, tokenResponse.IdToken)
	require.NotNil(t, tokenResponse.RefreshToken)
	require.Equal(t, "bearer", tokenResponse.TokenType)
	require.NotZero(t, tokenResponse.ExpiresIn)
	require.Equal(t, "openid email", tokenResponse.Scope)

	// Verify user is now logged in
	user, err := f.userRepo.GetByEmail(testUserEmail)
	require.NoError(t, err)
	require.True(t, user.LoggedIn)
}

// TestToken_InvalidClient tests token request with invalid client
func TestToken_InvalidClient(t *testing.T) {
	f := setupTestFixture(t)

	tokenParams := oauth2.TokenRequest{
		ClientID: "invalid-client",
		Code:     "some-code",
	}

	_, err := f.service.Token(tokenParams)

	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid client")
}

// TestToken_InvalidCode tests token request with invalid authorization code
func TestToken_InvalidCode(t *testing.T) {
	f := setupTestFixture(t)
	f.createTestClient(t, defaultTestClient())

	tokenParams := oauth2.TokenRequest{
		ClientID: testClientID,
		Code:     "invalid-code",
	}

	_, err := f.service.Token(tokenParams)

	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid authorization code")
}

// TestToken_WrongClientSecret tests token exchange with wrong client secret
func TestToken_WrongClientSecret(t *testing.T) {
	f := setupTestFixture(t)
	f.setupStandardTestEnvironment(t)

	// Complete authorization flow
	authCode := performAuthorizationFlow(t, f, testUserEmail, testUserPassword)

	// Try to exchange code with wrong secret
	_, err := f.service.Token(oauth2.TokenRequest{
		ClientID:     testClientID,
		ClientSecret: "wrong-secret",
		Code:         authCode,
	})

	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid client secret")
}

// TestToken_ClientCredentialsGrant tests client credentials grant
func TestToken_ClientCredentialsGrant(t *testing.T) {
	f := setupTestFixture(t)
	f.setupMinimalTestEnvironment(t)

	// Request tokens using client credentials grant (no code, just credentials)
	tokens, err := f.service.Token(oauth2.TokenRequest{
		ClientID:     testClientID,
		ClientSecret: testClientSecret,
		// No Code - this triggers client credentials grant
	})

	require.NoError(t, err)
	require.NotNil(t, tokens)
	require.NotNil(t, tokens.AccessToken)
}

// TestRefreshToken_Success tests successful refresh token exchange
func TestRefreshToken_Success(t *testing.T) {
	f := setupTestFixture(t)
	f.setupStandardTestEnvironment(t)

	// Get initial tokens
	authCode := performAuthorizationFlow(t, f, testUserEmail, testUserPassword)
	initialTokens, err := f.service.Token(oauth2.TokenRequest{
		ClientID: testClientID,
		Code:     authCode,
	})
	require.NoError(t, err)
	require.NotNil(t, initialTokens.RefreshToken)

	// Use refresh token to get new tokens
	refreshParams := oauth2.TokenRequest{
		ClientID:     testClientID,
		RefreshToken: *initialTokens.RefreshToken,
	}

	newTokens, err := f.service.Token(refreshParams)

	require.NoError(t, err)
	require.NotNil(t, newTokens.AccessToken)
	require.NotNil(t, newTokens.IdToken)
	require.NotNil(t, newTokens.RefreshToken)
	require.NotEqual(t, *initialTokens.RefreshToken, *newTokens.RefreshToken, "Refresh token should rotate")
}

// TestIntrospectToken_ActiveToken tests introspection of valid token
func TestIntrospectToken_ActiveToken(t *testing.T) {
	f := setupTestFixture(t)
	f.setupStandardTestEnvironment(t)

	// Get tokens
	authCode := performAuthorizationFlow(t, f, testUserEmail, testUserPassword)
	tokens, err := f.service.Token(oauth2.TokenRequest{
		ClientID: testClientID,
		Code:     authCode,
	})
	require.NoError(t, err)

	// Introspect the access token
	introspection, err := f.service.IntrospectToken(
		*tokens.AccessToken,
		testClientID,
		testClientSecret,
	)

	require.NoError(t, err)
	require.True(t, introspection.Active)
	require.Equal(t, testUserID, utils.Value(introspection.Sub))
	require.Equal(t, audience, utils.Value(introspection.Aud))
	require.Equal(t, issuer, utils.Value(introspection.Iss))
	require.Equal(t, testTenantID, introspection.Tenant)
	require.Equal(t, []string{"tenant_user"}, introspection.Roles)
}

// TestIntrospectToken_InvalidCredentials tests introspection with wrong credentials
func TestIntrospectToken_InvalidCredentials(t *testing.T) {
	f := setupTestFixture(t)
	f.createTestClient(t, defaultTestClient())

	introspection, err := f.service.IntrospectToken(
		"some-token",
		testClientID,
		"wrong-secret",
	)

	require.NoError(t, err) // Should not error but return inactive
	require.False(t, introspection.Active)
}

// TestRevokeToken_AccessToken tests revoking an access token
func TestRevokeToken_AccessToken(t *testing.T) {
	f := setupTestFixture(t)
	f.setupStandardTestEnvironment(t)

	// Get tokens
	authCode := performAuthorizationFlow(t, f, testUserEmail, testUserPassword)
	tokens, err := f.service.Token(oauth2.TokenRequest{
		ClientID: testClientID,
		Code:     authCode,
	})
	require.NoError(t, err)

	// Verify token is active
	introspection, err := f.service.IntrospectToken(*tokens.AccessToken, testClientID, testClientSecret)
	require.NoError(t, err)
	require.True(t, introspection.Active)

	// Revoke the token
	err = f.service.RevokeToken(
		*tokens.AccessToken,
		"access_token",
		testClientID,
		testClientSecret,
	)
	require.NoError(t, err)

	// Verify token is now inactive
	introspection, err = f.service.IntrospectToken(*tokens.AccessToken, testClientID, testClientSecret)
	require.NoError(t, err)
	require.False(t, introspection.Active, "Token should be revoked")
}

// TestRevokeToken_RefreshToken tests revoking a refresh token
func TestRevokeToken_RefreshToken(t *testing.T) {
	f := setupTestFixture(t)
	f.setupStandardTestEnvironment(t)

	// Get tokens
	authCode := performAuthorizationFlow(t, f, testUserEmail, testUserPassword)
	tokens, err := f.service.Token(oauth2.TokenRequest{
		ClientID: testClientID,
		Code:     authCode,
	})
	require.NoError(t, err)

	// Revoke refresh token
	err = f.service.RevokeToken(
		*tokens.RefreshToken,
		"refresh_token",
		testClientID,
		testClientSecret,
	)
	require.NoError(t, err)

	// Try to use revoked refresh token
	_, err = f.service.Token(oauth2.TokenRequest{
		ClientID:     testClientID,
		RefreshToken: *tokens.RefreshToken,
	})
	require.Error(t, err, "Should not be able to use revoked refresh token")
}

// TestRevokeToken_InvalidClient tests revoking token with invalid client credentials
func TestRevokeToken_InvalidClient(t *testing.T) {
	f := setupTestFixture(t)
	f.setupStandardTestEnvironment(t)

	// Get tokens
	authCode := performAuthorizationFlow(t, f, testUserEmail, testUserPassword)
	tokens, err := f.service.Token(oauth2.TokenRequest{
		ClientID: testClientID,
		Code:     authCode,
	})
	require.NoError(t, err)

	// Try to revoke with wrong client secret
	err = f.service.RevokeToken(
		*tokens.AccessToken,
		"access_token",
		testClientID,
		"wrong-secret",
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid client credentials")

	// Try to revoke with wrong client ID
	err = f.service.RevokeToken(
		*tokens.AccessToken,
		"access_token",
		"wrong-client-id",
		testClientSecret,
	)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid client credentials")
}

// TestUserInfo_Success tests retrieving user info
func TestUserInfo_Success(t *testing.T) {
	f := setupTestFixture(t)
	f.setupMinimalTestEnvironment(t)

	user := defaultTestUser()
	user.FirstName = "John"
	user.LastName = "Doe"
	user.Username = "johndoe"
	f.createTestUser(t, user)

	// Get tokens
	authCode := performAuthorizationFlow(t, f, testUserEmail, testUserPassword)
	tokens, err := f.service.Token(oauth2.TokenRequest{
		ClientID: testClientID,
		Code:     authCode,
	})
	require.NoError(t, err)

	// Get user info
	userInfo, err := f.service.UserInfo(*tokens.AccessToken)

	require.NoError(t, err)
	require.Equal(t, testUserID, userInfo["sub"])
	require.Equal(t, testUserEmail, userInfo["email"])
	require.Equal(t, true, userInfo["email_verified"])
	require.Equal(t, "John Doe", userInfo["name"])
	require.Equal(t, "John", userInfo["given_name"])
	require.Equal(t, "Doe", userInfo["family_name"])
	require.Equal(t, "johndoe", userInfo["preferred_username"])
}

// TestUserInfo_InvalidToken tests user info with invalid token
func TestUserInfo_InvalidToken(t *testing.T) {
	f := setupTestFixture(t)

	_, err := f.service.UserInfo("invalid-token")

	require.Error(t, err)
}

// performAuthorizationFlow is a helper that completes the full auth flow and returns an auth code
func performAuthorizationFlow(t *testing.T, f *testFixture, email, password string) string {
	t.Helper()

	var sessionID string
	var authCode string

	params := &oauth2.AuthorizationParameters{
		ClientID:     testClientID,
		ResponseType: "code",
		RedirectURI:  testRedirectURI,
		ResponseMode: oauth2.QueryResponseMode,
		Scope:        "openid email",
		State:        testState,
	}

	err := f.service.Authorize(params, func(sid string) { sessionID = sid }, nil)
	require.NoError(t, err)

	redirectFunc := func(uri string, mode oauth2.ResponseModeType, code, state string) {
		authCode = code
	}

	err = f.service.Login(sessionID, email, password, redirectFunc, nil)
	require.NoError(t, err)
	require.NotEmpty(t, authCode)

	return authCode
}

// TestLogout_Success tests successful logout
func TestLogout_Success(t *testing.T) {
	f := setupTestFixture(t)
	f.setupStandardTestEnvironment(t)

	// Get tokens first
	authCode := performAuthorizationFlow(t, f, testUserEmail, testUserPassword)
	tokens, err := f.service.Token(oauth2.TokenRequest{
		ClientID: testClientID,
		Code:     authCode,
	})
	require.NoError(t, err)
	require.NotNil(t, tokens.RefreshToken)

	// Verify user is logged in
	user, err := f.userRepo.GetByEmail(testUserEmail)
	require.NoError(t, err)
	require.True(t, user.LoggedIn)

	// Logout - requires access token for authentication
	err = f.service.Logout(*tokens.AccessToken, *tokens.RefreshToken)
	require.NoError(t, err)

	// Verify user is logged out
	user, err = f.userRepo.GetByEmail(testUserEmail)
	require.NoError(t, err)
	require.False(t, user.LoggedIn)

	// Verify refresh token is invalidated
	_, err = f.service.Token(oauth2.TokenRequest{
		ClientID:     testClientID,
		RefreshToken: *tokens.RefreshToken,
	})
	require.Error(t, err, "Should not be able to use refresh token after logout")

	// Verify access token is revoked
	introspection, err := f.service.IntrospectToken(*tokens.AccessToken, testClientID, testClientSecret)
	require.NoError(t, err)
	require.False(t, introspection.Active, "Access token should be revoked after logout")
}

// TestLogout_UserNotFound tests logout with invalid access token
func TestLogout_UserNotFound(t *testing.T) {
	f := setupTestFixture(t)

	// Try to logout with invalid access token
	err := f.service.Logout("invalid-token", "some-refresh-token")
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid access token")
}

// TestGetJWKS_WithAsymmetricKey tests JWKS with RSA key
func TestGetJWKS_WithAsymmetricKey(t *testing.T) {
	// Setup with RSA signer
	ur := fakeuserrepo.NewFakeUserRepo()
	sr := fakesessionrepo.NewFakeSessionRepo()
	cr := fakeclientrepo.NewFakeClientRepo()
	tr := tenantrepofakes.NewFakeTenantRepo()
	rtr := refreshrepofake.NewFakeRefreshTokenRepo()

	cfg := config.New()

	repos := auth.Repos{
		Users:         ur,
		Sessions:      sr,
		Clients:       cr,
		Tenants:       tr,
		RefreshTokens: rtr,
	}

	authService, err := auth.NewAuthorizationService(repos, cfg)
	require.NoError(t, err)

	// Create tenant with RSA key
	tenant := &tenants.Tenant{
		ID:     testTenantID,
		Name:   "Test Tenant",
		Domain: "https://tenant.example.com",
		Config: tenants.TenantConfig{
			Issuer:             issuer,
			Audience:           audience,
			AccessTokenExpiry:  15 * time.Minute,
			IDTokenExpiry:      time.Hour,
			RefreshTokenExpiry: 7 * 24 * time.Hour,
		},
		Keys: tenants.TenantKeys{
			KeyID: "test-key-1",
		},
	}

	// Generate RSA key material for the tenant
	err = keys.GenerateKeysForTenant(tenant)
	require.NoError(t, err)

	err = tr.Upsert(tenant)
	require.NoError(t, err)

	// Get JWKS
	jwks, err := authService.GetJWKS(testTenantID)
	require.NoError(t, err)
	require.NotNil(t, jwks)
	require.Len(t, jwks.Keys, 1)
	require.Equal(t, "RSA", jwks.Keys[0].Kty)
	require.Equal(t, "test-key-1", jwks.Keys[0].Kid)
}

// TestCleanupRevokedTokens tests cleanup functionality
func TestCleanupRevokedTokens(t *testing.T) {
	f := setupTestFixture(t)

	// Should not panic
	f.service.CleanupRevokedTokens()
}

// TestNewAuthorizationService_MissingDependencies tests validation
func TestNewAuthorizationService_MissingDependencies(t *testing.T) {
	tests := []struct {
		name      string
		repos     auth.Repos
		expectErr string
	}{
		{
			name: "missing users repo",
			repos: auth.Repos{
				Users:         nil,
				Sessions:      fakesessionrepo.NewFakeSessionRepo(),
				Clients:       fakeclientrepo.NewFakeClientRepo(),
				Tenants:       tenantrepofakes.NewFakeTenantRepo(),
				RefreshTokens: refreshrepofake.NewFakeRefreshTokenRepo(),
			},
			expectErr: "Users repo is required",
		},
		{
			name: "missing sessions repo",
			repos: auth.Repos{
				Users:         fakeuserrepo.NewFakeUserRepo(),
				Sessions:      nil,
				Clients:       fakeclientrepo.NewFakeClientRepo(),
				Tenants:       tenantrepofakes.NewFakeTenantRepo(),
				RefreshTokens: refreshrepofake.NewFakeRefreshTokenRepo(),
			},
			expectErr: "Sessions repo is required",
		},
		{
			name: "missing clients repo",
			repos: auth.Repos{
				Users:         fakeuserrepo.NewFakeUserRepo(),
				Sessions:      fakesessionrepo.NewFakeSessionRepo(),
				Clients:       nil,
				Tenants:       tenantrepofakes.NewFakeTenantRepo(),
				RefreshTokens: refreshrepofake.NewFakeRefreshTokenRepo(),
			},
			expectErr: "Clients repo is required",
		},
		{
			name: "missing tenants repo",
			repos: auth.Repos{
				Users:         fakeuserrepo.NewFakeUserRepo(),
				Sessions:      fakesessionrepo.NewFakeSessionRepo(),
				Clients:       fakeclientrepo.NewFakeClientRepo(),
				Tenants:       nil,
				RefreshTokens: refreshrepofake.NewFakeRefreshTokenRepo(),
			},
			expectErr: "Tenants repo is required",
		},
		{
			name: "missing refresh token repo",
			repos: auth.Repos{
				Users:    fakeuserrepo.NewFakeUserRepo(),
				Sessions: fakesessionrepo.NewFakeSessionRepo(),
				Clients:  fakeclientrepo.NewFakeClientRepo(),
				Tenants:  tenantrepofakes.NewFakeTenantRepo(),
			},
			expectErr: "refreshTokenRepo is required",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := auth.NewAuthorizationService(tt.repos, config.New())
			require.Error(t, err)
			require.Contains(t, err.Error(), tt.expectErr)
		})
	}

	// Test missing config
	t.Run("missing config", func(t *testing.T) {
		repos := auth.Repos{
			Users:         fakeuserrepo.NewFakeUserRepo(),
			Sessions:      fakesessionrepo.NewFakeSessionRepo(),
			Clients:       fakeclientrepo.NewFakeClientRepo(),
			Tenants:       tenantrepofakes.NewFakeTenantRepo(),
			RefreshTokens: refreshrepofake.NewFakeRefreshTokenRepo(),
		}
		_, err := auth.NewAuthorizationService(repos, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "config is required")
	})
}

// TestWithNowTime tests the time function option
func TestWithNowTime(t *testing.T) {
	f := setupTestFixture(t)

	fixedTime := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)

	// Save original time function and restore after test
	originalNowTimeFunc := auth.NowTimeFunc
	defer func() { auth.NowTimeFunc = originalNowTimeFunc }()

	// Set custom time function
	auth.NowTimeFunc = func() time.Time { return fixedTime }

	repos := auth.Repos{
		Users:         f.userRepo,
		Sessions:      f.sessionRepo,
		Clients:       f.clientRepo,
		Tenants:       f.tenantsRepo,
		RefreshTokens: f.refreshTokenRepo,
	}

	serviceWithCustomTime, err := auth.NewAuthorizationService(
		repos,
		config.New(),
	)
	require.NoError(t, err)
	require.NotNil(t, serviceWithCustomTime)
}

// TestCheckCodeChallenge_AllMethods tests PKCE validation
func TestCheckCodeChallenge_AllMethods(t *testing.T) {
	f := setupTestFixture(t)
	client := publicTestClient()
	client.ID = "pkce-test-client"
	f.createTestClient(t, client)
	f.setupMinimalTestEnvironment(t)
	f.createTestUser(t, defaultTestUser())

	// Create confidential client for no-PKCE test
	confidentialClient := defaultTestClient()
	confidentialClient.ID = "pkce-confidential-client"
	f.createTestClient(t, confidentialClient)

	tests := []struct {
		name                string
		clientID            string
		codeChallenge       string
		codeChallengeMethod oauth2.CodeMethodType
		codeVerifier        string
		shouldSucceed       bool
	}{
		{
			name:                "valid S256 challenge",
			clientID:            client.ID,
			codeChallenge:       testCodeChallenge,
			codeChallengeMethod: oauth2.CodeMethodTypeS256,
			codeVerifier:        testCodeVerifier,
			shouldSucceed:       true,
		},
		{
			name:                "valid plain challenge",
			clientID:            client.ID,
			codeChallenge:       "plaintext-challenge",
			codeChallengeMethod: oauth2.CodeMethodTypeNone,
			codeVerifier:        "plaintext-challenge",
			shouldSucceed:       true,
		},
		{
			name:                "invalid S256 challenge",
			clientID:            client.ID,
			codeChallenge:       "wrong-challenge",
			codeChallengeMethod: oauth2.CodeMethodTypeS256,
			codeVerifier:        testCodeVerifier,
			shouldSucceed:       false,
		},
		{
			name:                "no PKCE with confidential client",
			clientID:            confidentialClient.ID,
			codeChallenge:       "",
			codeChallengeMethod: "",
			codeVerifier:        "",
			shouldSucceed:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sessionID string
			params := &oauth2.AuthorizationParameters{
				ClientID:            tt.clientID,
				ResponseType:        oauth2.CodeResponseType,
				RedirectURI:         testRedirectURI,
				Scope:               "openid",
				State:               testState,
				CodeChallenge:       tt.codeChallenge,
				CodeChallengeMethod: tt.codeChallengeMethod,
			}

			err := f.service.Authorize(params, func(sid string) { sessionID = sid }, nil)
			require.NoError(t, err)

			var authCode string
			redirectFunc := func(uri string, mode oauth2.ResponseModeType, code, state string) {
				authCode = code
			}

			err = f.service.Login(sessionID, testUserEmail, testUserPassword, redirectFunc, nil)
			require.NoError(t, err)

			// Try to exchange code
			tokenParams := oauth2.TokenRequest{
				ClientID:     tt.clientID,
				Code:         authCode,
				CodeVerifier: tt.codeVerifier,
			}

			_, err = f.service.Token(tokenParams)
			if tt.shouldSucceed {
				require.NoError(t, err, "Token exchange should succeed")
			} else {
				require.Error(t, err, "Token exchange should fail")
				require.Contains(t, err.Error(), "code challenge")
			}
		})
	}
}

// TestToken_ExpiredAuthCode tests auth code timeout
func TestToken_ExpiredAuthCode(t *testing.T) {
	f := setupTestFixture(t)
	f.setupStandardTestEnvironment(t)

	// Save original time function and restore after test
	originalNowTimeFunc := auth.NowTimeFunc
	defer func() { auth.NowTimeFunc = originalNowTimeFunc }()

	// Create service with custom time that advances
	pastTime := time.Now().Add(-20 * time.Minute) // 20 minutes ago (timeout is 15)
	repos := auth.Repos{
		Users:         f.userRepo,
		Sessions:      f.sessionRepo,
		Clients:       f.clientRepo,
		Tenants:       f.tenantsRepo,
		RefreshTokens: f.refreshTokenRepo,
	}

	// Set past time for authorization
	auth.NowTimeFunc = func() time.Time { return pastTime }

	// Create service with past time
	serviceWithPastTime, err := auth.NewAuthorizationService(
		repos,
		config.New(),
	)
	require.NoError(t, err)

	// Perform authorization with past time
	var sessionID string
	params := &oauth2.AuthorizationParameters{
		ClientID:     testClientID,
		ResponseType: oauth2.CodeResponseType,
		RedirectURI:  testRedirectURI,
		Scope:        "openid",
		State:        testState,
	}

	err = serviceWithPastTime.Authorize(params, func(sid string) { sessionID = sid }, nil)
	require.NoError(t, err)

	var authCode string
	redirectFunc := func(uri string, mode oauth2.ResponseModeType, code, state string) {
		authCode = code
	}

	err = serviceWithPastTime.Login(sessionID, testUserEmail, testUserPassword, redirectFunc, nil)
	require.NoError(t, err)

	// Try to exchange code with normal service (current time)
	_, err = f.service.Token(oauth2.TokenRequest{
		ClientID: testClientID,
		Code:     authCode,
	})

	require.Error(t, err)
	require.Contains(t, err.Error(), "authorization code expired")
}

// TestUserInfo_BlockedUser tests userinfo with blocked user
func TestUserInfo_BlockedUser(t *testing.T) {
	f := setupTestFixture(t)
	f.setupMinimalTestEnvironment(t)

	user := defaultTestUser()
	f.createTestUser(t, user)

	// Get tokens
	authCode := performAuthorizationFlow(t, f, testUserEmail, testUserPassword)
	tokens, err := f.service.Token(oauth2.TokenRequest{
		ClientID: testClientID,
		Code:     authCode,
	})
	require.NoError(t, err)

	// Block the user
	err = f.userRepo.SetBlocked(testUserEmail, true)
	require.NoError(t, err)

	// Try to get user info
	_, err = f.service.UserInfo(*tokens.AccessToken)
	require.Error(t, err)
	require.Contains(t, err.Error(), "blocked")
}

// TestUserInfo_UnverifiedUser tests userinfo with unverified user
func TestUserInfo_UnverifiedUser(t *testing.T) {
	f := setupTestFixture(t)
	f.setupMinimalTestEnvironment(t)

	user := defaultTestUser()
	f.createTestUser(t, user)

	// Get tokens
	authCode := performAuthorizationFlow(t, f, testUserEmail, testUserPassword)
	tokens, err := f.service.Token(oauth2.TokenRequest{
		ClientID: testClientID,
		Code:     authCode,
	})
	require.NoError(t, err)

	// Unverify the user
	err = f.userRepo.SetVerified(testUserEmail, false)
	require.NoError(t, err)

	// Try to get user info
	_, err = f.service.UserInfo(*tokens.AccessToken)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not verified")
}

// TestTokenUser_EmptyToken tests tokenUser with empty token
func TestTokenUser_EmptyToken(t *testing.T) {
	f := setupTestFixture(t)
	f.setupStandardTestEnvironment(t)

	// Authorize with empty current token (should succeed)
	params := &oauth2.AuthorizationParameters{
		ClientID:           testClientID,
		ResponseType:       oauth2.CodeResponseType,
		RedirectURI:        testRedirectURI,
		Scope:              "openid",
		CurrentAccessToken: "", // Empty token
	}

	var sessionID string
	err := f.service.Authorize(params, func(sid string) { sessionID = sid }, nil)
	require.NoError(t, err)
	require.NotEmpty(t, sessionID)
}

// TestTokenUser_InvalidToken tests tokenUser with invalid token
func TestTokenUser_InvalidToken(t *testing.T) {
	f := setupTestFixture(t)
	f.setupStandardTestEnvironment(t)

	// Authorize with invalid token (should succeed - token just ignored)
	params := &oauth2.AuthorizationParameters{
		ClientID:           testClientID,
		ResponseType:       oauth2.CodeResponseType,
		RedirectURI:        testRedirectURI,
		Scope:              "openid",
		CurrentAccessToken: "invalid-token-xyz",
	}

	var sessionID string
	err := f.service.Authorize(params, func(sid string) { sessionID = sid }, nil)
	require.NoError(t, err)
	require.NotEmpty(t, sessionID)
}

// TestTokenUser_ValidTokenBlockedUser tests tokenUser with valid token but blocked user
// Note: Due to a bug in tokenUser (errors.Wrap with nil err), blocked users with valid tokens
// are not currently rejected during authorization
func TestTokenUser_ValidTokenBlockedUser(t *testing.T) {
	f := setupTestFixture(t)
	f.setupStandardTestEnvironment(t)

	// Get valid tokens
	authCode := performAuthorizationFlow(t, f, testUserEmail, testUserPassword)
	tokens, err := f.service.Token(oauth2.TokenRequest{
		ClientID: testClientID,
		Code:     authCode,
	})
	require.NoError(t, err)

	// Block the user
	err = f.userRepo.SetBlocked(testUserEmail, true)
	require.NoError(t, err)

	// Try to authorize with the token - should now fail (bug fixed)
	params := &oauth2.AuthorizationParameters{
		ClientID:           testClientID,
		ResponseType:       oauth2.CodeResponseType,
		RedirectURI:        testRedirectURI,
		Scope:              "openid",
		CurrentAccessToken: *tokens.AccessToken,
	}

	err = f.service.Authorize(params, func(sid string) {}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "blocked")
}

// TestTokenUser_ValidTokenUnverifiedUser tests tokenUser with valid token but unverified user
func TestTokenUser_ValidTokenUnverifiedUser(t *testing.T) {
	f := setupTestFixture(t)
	f.setupStandardTestEnvironment(t)

	// Get valid tokens
	authCode := performAuthorizationFlow(t, f, testUserEmail, testUserPassword)
	tokens, err := f.service.Token(oauth2.TokenRequest{
		ClientID: testClientID,
		Code:     authCode,
	})
	require.NoError(t, err)

	// Unverify the user
	err = f.userRepo.SetVerified(testUserEmail, false)
	require.NoError(t, err)

	// Try to authorize with the token - should now fail (bug fixed)
	params := &oauth2.AuthorizationParameters{
		ClientID:           testClientID,
		ResponseType:       oauth2.CodeResponseType,
		RedirectURI:        testRedirectURI,
		Scope:              "openid",
		CurrentAccessToken: *tokens.AccessToken,
	}

	err = f.service.Authorize(params, func(sid string) {}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "not verified")
}

// TestTokenUser_ValidTokenWrongTenant tests tokenUser with valid token but wrong tenant
func TestTokenUser_ValidTokenWrongTenant(t *testing.T) {
	f := setupTestFixture(t)
	f.setupMinimalTestEnvironment(t)

	// Create user in tenant-1
	user := defaultTestUser()
	user.TenantIDs = []string{testTenantID}
	f.createTestUser(t, user)

	// Get valid tokens for tenant-1
	authCode := performAuthorizationFlow(t, f, testUserEmail, testUserPassword)
	tokens, err := f.service.Token(oauth2.TokenRequest{
		ClientID: testClientID,
		Code:     authCode,
	})
	require.NoError(t, err)

	// Create a second tenant
	f.createTestTenant(t, "tenant-2", "Tenant 2", "https://tenant2.example.com")

	// Create client for tenant-2
	client2 := defaultTestClient()
	client2.ID = "client-2"
	client2.TenantID = "tenant-2"
	f.createTestClient(t, client2)

	// Try to authorize in tenant-2 with tenant-1 token - should fail
	params := &oauth2.AuthorizationParameters{
		ClientID:           client2.ID,
		ResponseType:       oauth2.CodeResponseType,
		RedirectURI:        testRedirectURI,
		Scope:              "openid",
		RequestedTenantID:  "tenant-2",
		CurrentAccessToken: *tokens.AccessToken,
	}

	err = f.service.Authorize(params, func(sid string) {}, nil)
	require.Error(t, err)
	require.Contains(t, err.Error(), "User not in Tenant")
}

// TestMFAAuth_Placeholder tests MFA auth method (currently unimplemented)
func TestMFAAuth_Placeholder(t *testing.T) {
	f := setupTestFixture(t)

	// MFAAuth currently returns nil (unimplemented)
	err := f.service.MFAAuth("session-id", "123456", nil)
	require.NoError(t, err, "MFAAuth should return nil (not yet implemented)")
}

// TestCleanupExpiredSessions_Placeholder tests cleanup method
func TestCleanupExpiredSessions_Placeholder(t *testing.T) {
	f := setupTestFixture(t)

	// CleanupExpiredSessions currently does nothing
	err := f.service.CleanupExpiredSessions()
	require.NoError(t, err, "CleanupExpiredSessions should not error")
}

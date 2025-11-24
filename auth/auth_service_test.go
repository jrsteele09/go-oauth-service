package auth_test

import (
	"testing"
	"time"

	"github.com/jrsteele09/go-auth-server/auth"
	fakesessionrepo "github.com/jrsteele09/go-auth-server/auth/repofakes"
	"github.com/jrsteele09/go-auth-server/clients"
	fakeclientrepo "github.com/jrsteele09/go-auth-server/clients/fakerepo"
	"github.com/jrsteele09/go-auth-server/internal/utils"
	"github.com/jrsteele09/go-auth-server/tenants"
	tenantrepofakes "github.com/jrsteele09/go-auth-server/tenants/repofakes"
	"github.com/jrsteele09/go-auth-server/token"
	tokenfakerepo "github.com/jrsteele09/go-auth-server/token/repofake"
	"github.com/jrsteele09/go-auth-server/users"
	fakeuserrepo "github.com/jrsteele09/go-auth-server/users/repofake"
	"github.com/stretchr/testify/require"
)

const (
	secretStr         = "1234"
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
	testNonce         = "random-nonce-value"
)

// testFixture holds all test dependencies
type testFixture struct {
	userRepo     users.UserRepo
	sessionRepo  auth.SessionRepo
	clientRepo   clients.Repo
	tenantsRepo  tenants.Repo
	tokenCreator *token.Manager
	service      *auth.AuthorizationService
}

// testUser represents a test user with common fields
type testUser struct {
	ID        string
	Email     string
	Username  string
	Password  string
	FirstName string
	LastName  string
	Roles     []string
	TenantIDs []string
	Verified  bool
	Blocked   bool
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

	signer := token.NewHMACSigner(secretStr)
	tc := token.New(
		tokenfakerepo.NewFakeTokensRepo(),
		ur,
		signer,
		token.WithTokenExpiry(10*time.Minute, 10*time.Hour, 1*time.Hour),
		token.WithIssuer(issuer),
		token.WithAudience(audience),
	)

	repos := auth.Repos{
		Users:    ur,
		Sessions: sr,
		Clients:  cr,
		Tenants:  tr,
	}

	authService, err := auth.NewAuthorizationService(repos, tc)
	require.NoError(t, err)

	return &testFixture{
		userRepo:     ur,
		sessionRepo:  sr,
		clientRepo:   cr,
		tenantsRepo:  tr,
		tokenCreator: tc,
		service:      authService,
	}
}

// createTestUser creates and stores a test user
func (f *testFixture) createTestUser(t *testing.T, user testUser) {
	t.Helper()

	passwordHash, err := users.HashPassword(user.Password)
	require.NoError(t, err)

	err = f.userRepo.Upsert(&users.User{
		ID:           user.ID,
		Email:        user.Email,
		Username:     user.Username,
		PasswordHash: passwordHash,
		FirstName:    user.FirstName,
		LastName:     user.LastName,
		Roles:        user.Roles,
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

// createTestTenant creates and stores a test tenant
func (f *testFixture) createTestTenant(t *testing.T, id, name, domain string) {
	t.Helper()

	err := f.tenantsRepo.Upsert(&tenants.Tenant{
		ID:     id,
		Name:   name,
		Domain: domain,
	})
	require.NoError(t, err)
}

// defaultTestUser returns a default test user
func defaultTestUser() testUser {
	return testUser{
		ID:        testUserID,
		Email:     testUserEmail,
		Username:  "johndoe",
		Password:  testUserPassword,
		FirstName: "John",
		LastName:  "Doe",
		Roles:     []string{"user"},
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

// TestAuthorize_CreatesSession tests that Authorize creates a session and triggers login
func TestAuthorize_CreatesSession(t *testing.T) {
	f := setupTestFixture(t)
	f.createTestClient(t, defaultTestClient())
	f.createTestTenant(t, testTenantID, "Test Tenant", "https://tenant.example.com")

	var capturedSessionID string
	loginFunc := func(sessionID string) {
		capturedSessionID = sessionID
	}

	params := &auth.AuthorizationParameters{
		ClientID:     testClientID,
		ResponseType: "code",
		RedirectURI:  testRedirectURI,
		ResponseMode: auth.QueryResponseMode,
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

	params := &auth.AuthorizationParameters{
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

	params := &auth.AuthorizationParameters{
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

	params := &auth.AuthorizationParameters{
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

	params := &auth.AuthorizationParameters{
		ClientID:     testClientID,
		ResponseType: "code",
		RedirectURI:  testRedirectURI,
		Scope:        "invalid-scope", // Not in client's allowed scopes
	}

	err := f.service.Authorize(params, nil, nil)

	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid scope")
}

// TestLogin_Success tests successful login
func TestLogin_Success(t *testing.T) {
	f := setupTestFixture(t)
	f.createTestClient(t, defaultTestClient())
	f.createTestTenant(t, testTenantID, "Test Tenant", "https://tenant.example.com")
	f.createTestUser(t, defaultTestUser())

	// First authorize to create session
	var sessionID string
	params := &auth.AuthorizationParameters{
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
	redirectFunc := func(uri string, mode auth.ResponseModeType, code, state string) {
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
	f.createTestClient(t, defaultTestClient())
	f.createTestTenant(t, testTenantID, "Test Tenant", "https://tenant.example.com")
	f.createTestUser(t, defaultTestUser())

	var sessionID string
	params := &auth.AuthorizationParameters{
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
	f.createTestClient(t, defaultTestClient())
	f.createTestTenant(t, testTenantID, "Test Tenant", "https://tenant.example.com")

	user := defaultTestUser()
	user.TenantIDs = []string{"different-tenant"} // Not in test tenant
	f.createTestUser(t, user)

	var sessionID string
	params := &auth.AuthorizationParameters{
		ClientID:     testClientID,
		ResponseType: "code",
		RedirectURI:  testRedirectURI,
		Scope:        "openid",
	}

	err := f.service.Authorize(params, func(sid string) { sessionID = sid }, nil)
	require.NoError(t, err)

	redirectFunc := func(uri string, mode auth.ResponseModeType, code, state string) {}
	err = f.service.Login(sessionID, testUserEmail, testUserPassword, redirectFunc, nil)

	require.Error(t, err)
	require.Contains(t, err.Error(), "incorrect Tenant")
}

// TestToken_ExchangeCodeSuccess tests successful token exchange
func TestToken_ExchangeCodeSuccess(t *testing.T) {
	f := setupTestFixture(t)
	f.createTestClient(t, defaultTestClient())
	f.createTestTenant(t, testTenantID, "Test Tenant", "https://tenant.example.com")
	f.createTestUser(t, defaultTestUser())

	// Complete authorization flow
	authCode := performAuthorizationFlow(t, f, testUserEmail, testUserPassword)

	// Exchange code for tokens
	tokenParams := token.TokenParameters{
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

	tokenParams := token.TokenParameters{
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

	tokenParams := token.TokenParameters{
		ClientID: testClientID,
		Code:     "invalid-code",
	}

	_, err := f.service.Token(tokenParams)

	require.Error(t, err)
	require.Contains(t, err.Error(), "Auth Code invalid")
}

// TestRefreshToken_Success tests successful refresh token exchange
func TestRefreshToken_Success(t *testing.T) {
	f := setupTestFixture(t)
	f.createTestClient(t, defaultTestClient())
	f.createTestTenant(t, testTenantID, "Test Tenant", "https://tenant.example.com")
	f.createTestUser(t, defaultTestUser())

	// Get initial tokens
	authCode := performAuthorizationFlow(t, f, testUserEmail, testUserPassword)
	initialTokens, err := f.service.Token(token.TokenParameters{
		ClientID: testClientID,
		Code:     authCode,
	})
	require.NoError(t, err)
	require.NotNil(t, initialTokens.RefreshToken)

	// Use refresh token to get new tokens
	refreshParams := token.TokenParameters{
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
	f.createTestClient(t, defaultTestClient())
	f.createTestTenant(t, testTenantID, "Test Tenant", "https://tenant.example.com")
	f.createTestUser(t, defaultTestUser())

	// Get tokens
	authCode := performAuthorizationFlow(t, f, testUserEmail, testUserPassword)
	tokens, err := f.service.Token(token.TokenParameters{
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
	require.Equal(t, []string{"user"}, introspection.Roles)
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
	f.createTestClient(t, defaultTestClient())
	f.createTestTenant(t, testTenantID, "Test Tenant", "https://tenant.example.com")
	f.createTestUser(t, defaultTestUser())

	// Get tokens
	authCode := performAuthorizationFlow(t, f, testUserEmail, testUserPassword)
	tokens, err := f.service.Token(token.TokenParameters{
		ClientID: testClientID,
		Code:     authCode,
	})
	require.NoError(t, err)

	// Verify token is active
	introspection, err := f.tokenCreator.Introspection(*tokens.AccessToken)
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
	introspection, err = f.tokenCreator.Introspection(*tokens.AccessToken)
	require.NoError(t, err)
	require.False(t, introspection.Active, "Token should be revoked")
}

// TestRevokeToken_RefreshToken tests revoking a refresh token
func TestRevokeToken_RefreshToken(t *testing.T) {
	f := setupTestFixture(t)
	f.createTestClient(t, defaultTestClient())
	f.createTestTenant(t, testTenantID, "Test Tenant", "https://tenant.example.com")
	f.createTestUser(t, defaultTestUser())

	// Get tokens
	authCode := performAuthorizationFlow(t, f, testUserEmail, testUserPassword)
	tokens, err := f.service.Token(token.TokenParameters{
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
	_, err = f.service.Token(token.TokenParameters{
		ClientID:     testClientID,
		RefreshToken: *tokens.RefreshToken,
	})
	require.Error(t, err, "Should not be able to use revoked refresh token")
}

// TestUserInfo_Success tests retrieving user info
func TestUserInfo_Success(t *testing.T) {
	f := setupTestFixture(t)
	f.createTestClient(t, defaultTestClient())
	f.createTestTenant(t, testTenantID, "Test Tenant", "https://tenant.example.com")

	user := defaultTestUser()
	user.FirstName = "John"
	user.LastName = "Doe"
	user.Username = "johndoe"
	f.createTestUser(t, user)

	// Get tokens
	authCode := performAuthorizationFlow(t, f, testUserEmail, testUserPassword)
	tokens, err := f.service.Token(token.TokenParameters{
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

	params := &auth.AuthorizationParameters{
		ClientID:     testClientID,
		ResponseType: "code",
		RedirectURI:  testRedirectURI,
		ResponseMode: auth.QueryResponseMode,
		Scope:        "openid email",
		State:        testState,
	}

	err := f.service.Authorize(params, func(sid string) { sessionID = sid }, nil)
	require.NoError(t, err)

	redirectFunc := func(uri string, mode auth.ResponseModeType, code, state string) {
		authCode = code
	}

	err = f.service.Login(sessionID, email, password, redirectFunc, nil)
	require.NoError(t, err)
	require.NotEmpty(t, authCode)

	return authCode
}

package token

import (
	"fmt"

	"github.com/jrsteele09/go-auth-server/internal/config"
	"github.com/jrsteele09/go-auth-server/internal/errors"
	"github.com/jrsteele09/go-auth-server/oauth2"
	"github.com/jrsteele09/go-auth-server/tenants"
	"github.com/jrsteele09/go-auth-server/token/jwt"
	"github.com/jrsteele09/go-auth-server/token/keys"
	"github.com/jrsteele09/go-auth-server/token/refresh"
	"github.com/jrsteele09/go-auth-server/token/revocation"
	"github.com/jrsteele09/go-auth-server/users"
)

// TokenSpecifics contains token generation parameters
type TokenSpecifics struct {
	Scope     string
	TenantID  string
	UserEmail string
	Nonce     string
}

// Manager coordinates JWT, refresh token, and revocation operations
type Manager struct {
	tenantRepo    tenants.Repo
	userRepo      users.UserRepo
	tenantSigners map[string]keys.Signer // Tenant-specific signers (key: tenantID)

	jwtCreator   *jwt.Creator
	jwtInspector *jwt.Inspector
	refreshMgr   *refresh.Manager
	revokedCache revocation.RevokedTokenCache

	config config.OAuthConfig
}

// NewManager creates a new token manager
func NewManager(repo refresh.Repo, userRepo users.UserRepo, tenantRepo tenants.Repo, cfg config.OAuthConfig) *Manager {
	revokedCache := revocation.NewInMemoryRevokedTokenCache()

	return &Manager{
		userRepo:      userRepo,
		tenantRepo:    tenantRepo,
		tenantSigners: make(map[string]keys.Signer),

		jwtCreator:   jwt.NewCreator(cfg),
		jwtInspector: jwt.NewInspector(tenantRepo, revokedCache),
		refreshMgr:   refresh.NewManager(repo, cfg),
		revokedCache: revokedCache,

		config: cfg,
	}
}

// CreateIDToken creates an OpenID Connect ID token
func (m *Manager) CreateIDToken(user *users.User, tenant *tenants.Tenant, clientID, nonce string) (*string, error) {
	signer, err := m.getSignerFromTenant(tenant)
	if err != nil {
		return nil, fmt.Errorf("failed to get signer for tenant: %w", err)
	}
	return m.jwtCreator.CreateIDToken(user, tenant, clientID, nonce, signer)
}

// CreateAccessToken creates an OAuth2 access token
func (m *Manager) CreateAccessToken(user *users.User, tenant *tenants.Tenant, clientID, scope string) (*string, error) {
	signer, err := m.getSignerFromTenant(tenant)
	if err != nil {
		return nil, fmt.Errorf("failed to get signer for tenant: %w", err)
	}
	return m.jwtCreator.CreateAccessToken(user, tenant, clientID, scope, signer)
}

// CreateRefreshToken generates a new refresh token
func (m *Manager) CreateRefreshToken(clientID, userID, tenantID, scope string) (*string, error) {
	return m.refreshMgr.Create(clientID, userID, tenantID, scope)
}

// Introspection validates and extracts information from a JWT token
func (m *Manager) Introspection(rawToken string) (*jwt.TokenIntrospection, error) {
	return m.jwtInspector.Introspect(rawToken, m.getSignerFromTenant)
}

// InvalidateRefreshToken removes a refresh token from storage
func (m *Manager) InvalidateRefreshToken(refreshToken string) {
	_ = m.refreshMgr.Delete(refreshToken)
}

// GenerateTokenResponse generates a complete token response
func (m *Manager) GenerateTokenResponse(parameters oauth2.TokenRequest, tokenSpecifics TokenSpecifics) (*oauth2.TokenResponse, error) {
	var idToken, accessToken, refreshToken *string

	// Handle refresh token grant
	if parameters.RefreshToken != "" {
		return m.handleRefreshTokenGrant(parameters)
	}

	tenant, err := m.tenantRepo.Get(tokenSpecifics.TenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant: %w", err)
	}

	// Handle user-delegated token (authorization code flow)
	if parameters.ClientSecret == "" && tokenSpecifics.UserEmail != "" {
		user, err := m.userRepo.GetByEmail(tokenSpecifics.UserEmail)
		if err != nil {
			return nil, fmt.Errorf("failed to get user by email: %w", err)
		}

		idToken, err = m.CreateIDToken(user, tenant, parameters.ClientID, tokenSpecifics.Nonce)
		if err != nil {
			return nil, fmt.Errorf("failed to create ID token: %w", err)
		}

		accessToken, err = m.CreateAccessToken(user, tenant, parameters.ClientID, tokenSpecifics.Scope)
		if err != nil {
			return nil, fmt.Errorf("failed to create access token: %w", err)
		}

		// Create refresh token if tenant has refresh token expiry configured
		if tenant.Config.GetRefreshTokenExpiry(m.config.GetDefaultRefreshTokenExpiry()) > 0 {
			refreshToken, err = m.CreateRefreshToken(parameters.ClientID, user.ID, tokenSpecifics.TenantID, tokenSpecifics.Scope)
			if err != nil {
				return nil, fmt.Errorf("failed to create refresh token: %w", err)
			}
		}

		return &oauth2.TokenResponse{
			AccessToken:  accessToken,
			IdToken:      idToken,
			TokenType:    "bearer",
			ExpiresIn:    int(tenant.Config.GetAccessTokenExpiry(m.config.GetDefaultAccessTokenExpiry()).Seconds()),
			RefreshToken: refreshToken,
			Scope:        tokenSpecifics.Scope,
		}, nil
	}

	// Handle client credentials token (machine-to-machine)
	if parameters.ClientSecret != "" {
		accessToken, err = m.CreateAccessToken(nil, tenant, parameters.ClientID, tokenSpecifics.Scope)
		if err != nil {
			return nil, fmt.Errorf("failed to create client access token: %w", err)
		}

		return &oauth2.TokenResponse{
			AccessToken:  accessToken,
			IdToken:      idToken,
			TokenType:    "bearer",
			ExpiresIn:    int(tenant.Config.GetAccessTokenExpiry(m.config.GetDefaultAccessTokenExpiry()).Seconds()),
			RefreshToken: refreshToken,
			Scope:        tokenSpecifics.Scope,
		}, nil
	}

	return nil, errors.ErrInvalidRequest
} // handleRefreshTokenGrant processes a refresh token grant
func (m *Manager) handleRefreshTokenGrant(parameters oauth2.TokenRequest) (*oauth2.TokenResponse, error) {
	// Get the refresh token from storage
	rt, err := m.refreshMgr.Get(parameters.RefreshToken)
	if err != nil {
		return nil, errors.ErrInvalidRefreshToken
	}

	// Load tenant for configuration
	tenant, err := m.tenantRepo.Get(rt.TenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to get tenant: %w", err)
	}

	// Check if refresh token has expired
	if m.refreshMgr.IsExpired(rt, tenant.Config.GetRefreshTokenExpiry(m.config.GetDefaultRefreshTokenExpiry())) {
		_ = m.refreshMgr.Delete(parameters.RefreshToken)
		return nil, errors.ErrRefreshTokenExpired
	}

	// Get the user
	user, err := m.userRepo.GetByID(rt.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found for refresh token: %w", err)
	}

	// Check if user is blocked or unverified
	if user.Blocked {
		return nil, errors.ErrUserBlocked
	}
	if !user.Verified {
		return nil, errors.ErrUserNotVerified
	}

	// Generate new access token
	accessToken, err := m.CreateAccessToken(user, tenant, rt.ClientID, rt.Scope)
	if err != nil {
		return nil, fmt.Errorf("failed to create access token: %w", err)
	}

	// Generate new ID token
	idToken, err := m.CreateIDToken(user, tenant, rt.ClientID, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create ID token: %w", err)
	}

	// Rotate refresh token (delete old, create new)
	newRefreshToken, err := m.CreateRefreshToken(rt.ClientID, rt.UserID, rt.TenantID, rt.Scope)
	if err != nil {
		return nil, fmt.Errorf("failed to create new refresh token: %w", err)
	}

	return &oauth2.TokenResponse{
		AccessToken:  accessToken,
		IdToken:      idToken,
		TokenType:    "bearer",
		ExpiresIn:    int(tenant.Config.GetAccessTokenExpiry(m.config.GetDefaultAccessTokenExpiry()).Seconds()),
		RefreshToken: newRefreshToken,
	}, nil
}

// GetJWKS returns the JSON Web Key Set for public key distribution
func (m *Manager) GetJWKS(tenant *tenants.Tenant) (*keys.JWKS, error) {
	signer, err := m.getSignerFromTenant(tenant)
	if err != nil {
		return nil, fmt.Errorf("failed to get signer for tenant: %w", err)
	}

	// Check if signer supports JWKS (only asymmetric signers do)
	keyPairSigner, ok := signer.(*keys.KeyPairSigner)
	if !ok {
		return nil, errors.ErrUnsupported
	}

	return keyPairSigner.GetJWKS()
}

// CleanupRevokedTokens removes expired tokens from the revocation cache
func (m *Manager) CleanupRevokedTokens() {
	if m.revokedCache != nil {
		m.revokedCache.Cleanup()
	}
}

// RevokeAccessToken revokes an access token by its JTI
func (m *Manager) RevokeAccessToken(rawToken string) error {
	jti, exp, err := m.jwtInspector.ParseAndExtractJTI(rawToken, m.getSignerFromTenant)
	if err != nil {
		return fmt.Errorf("failed to parse token for revocation: %w", err)
	}

	return m.revokedCache.Add(jti, exp)
}

// getSignerFromTenant creates and caches a signer from a tenant object
func (m *Manager) getSignerFromTenant(tenant *tenants.Tenant) (keys.Signer, error) {
	// Check cache first
	if signer, exists := m.tenantSigners[tenant.ID]; exists {
		return signer, nil
	}

	if !tenant.Keys.HasKeys() {
		return nil, fmt.Errorf("tenant %s has no key pair", tenant.ID)
	}

	// Try to create a signer from the tenant's key material
	signer, err := keys.CreateSigner(tenant.Keys.KeyID, tenant.Keys.PrivateKeyPEM, tenant.Keys.PublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to create signer for tenant %s: %w", tenant.ID, err)
	}

	// Cache it for future use
	m.tenantSigners[tenant.ID] = signer
	return signer, nil
}

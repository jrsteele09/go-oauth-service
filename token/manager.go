package token

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jrsteele09/go-auth-server/oauth2"
	"github.com/jrsteele09/go-auth-server/tenants"
	"github.com/jrsteele09/go-auth-server/users"
	"github.com/pkg/errors"
)

// NowTimeFunc returns the current time. It can be overridden in tests.
var NowTimeFunc = time.Now

type RefreshToken struct {
	Token    string
	UserID   string
	ClientID string
	TenantID string // Tenant context for tenant-specific expiry
	Scope    string // Original scope for token refresh
	Iat      time.Time
}

type TokenSpecifics struct {
	Scope     string
	TenantID  string
	UserEmail string
	Nonce     string
}

// TokenIntrospection represents the metadata information of an OAuth 2.0 token.
// The struct is designed to capture details from an introspection endpoint.
// The 'active' field indicates the state of the token - if it's false, other fields may not be populated.
type TokenIntrospection struct {
	Active bool     `json:"active"`           // True or false - Is the token valid
	Aud    *string  `json:"aud,omitempty"`    // Audience - the client ID that requested the token
	Exp    *int64   `json:"exp,omitempty"`    // Expiration
	Iat    *int64   `json:"iat,omitempty"`    // Issued at time
	Iss    *string  `json:"iss,omitempty"`    // Issuer of the token
	Roles  []string `json:"roles,omitempty"`  // Roles assigned to the User
	Tenant string   `json:"tenant,omitempty"` // Tenant
	Sub    *string  `json:"sub,omitempty"`    // Users unique ID
}

type Manager struct {
	tenantRepo    tenants.Repo      // Repository for tenant data
	tenantSigners map[string]Signer // Tenant-specific signers (key: tenantID)
	refreshrepo   RefreshTokenRepo
	userRepo      users.UserRepo    // Repository for user data
	revokedCache  RevokedTokenCache // Cache for revoked tokens
}

func New(repo RefreshTokenRepo, userRepo users.UserRepo, tenantRepo tenants.Repo) *Manager {
	return &Manager{
		refreshrepo:   repo,
		userRepo:      userRepo,
		tenantRepo:    tenantRepo,
		tenantSigners: make(map[string]Signer),
		revokedCache:  NewInMemoryRevokedTokenCache(),
	}
}

func (c *Manager) CreateIDToken(user *users.User, tenantID, clientID, nonce string) (*string, error) {
	tenant, err := c.getTenant(tenantID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get tenant")
	}

	signer, err := c.getSignerFromTenant(tenant)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get signer for tenant")
	}

	// ID Token contains identity claims only (OpenID Connect spec)
	// Authorization data like roles belongs in the access token
	claims := jwt.MapClaims{
		"iss":    tenant.Issuer,
		"sub":    user.ID,
		"aud":    clientID,
		"email":  user.Email,
		"name":   user.FirstName + " " + user.LastName,
		"tenant": tenant.ID,
		"iat":    int64(NowTimeFunc().Unix()),
		"exp":    int64(NowTimeFunc().Add(tenant.IDTokenExpiry).Unix()),
		"jti":    uuid.New().String(),
	}

	if nonce != "" {
		claims["nonce"] = nonce
	}

	// Sign the token with tenant-specific or default signer
	return c.signTokenWithSigner(claims, signer)
}

func (c *Manager) CreateAccessToken(user *users.User, tenantID, clientID, scope string) (*string, error) {
	tenant, err := c.getTenant(tenantID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get tenant")
	}

	signer, err := c.getSignerFromTenant(tenant)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get signer for tenant")
	}

	claims := jwt.MapClaims{
		"iss":       tenant.Issuer,                                             // The issuer of the token (tenant-specific)
		"aud":       tenant.Audience,                                           // The audience for which the token is intended (tenant-specific)
		"client_id": clientID,                                                  // The OAuth2 client that requested the token
		"scope":     scope,                                                     // OAuth2 scopes granted to this token
		"tenant":    tenant.ID,                                                 // Explicit tenant ID for multi-tenant context
		"iat":       int64(NowTimeFunc().Unix()),                               // Issued At: the time at which the token was issued
		"exp":       int64(NowTimeFunc().Add(tenant.AccessTokenExpiry).Unix()), // Expiry: when the token will expire
		"jti":       uuid.New().String(),                                       // Unique token ID for revocation
	}

	if user != nil {
		// User-delegated access token (authorization code flow)
		claims["sub"] = user.ID
		claims["roles"] = c.getCombinedRoles(user, tenant.ID)
		claims["token_type"] = "user"
	} else {
		// Client credentials token (machine-to-machine)
		claims["sub"] = clientID
		claims["token_type"] = "client"
	}

	// Sign the token with tenant-specific signer
	return c.signTokenWithSigner(claims, signer)
}

func (c *Manager) CreateRefreshToken(clientID, userID, tenantID, scope string) (*string, error) {
	if existingToken, err := c.refreshrepo.GetByUserID(userID); err == nil && existingToken != nil {
		if err := c.refreshrepo.Delete(existingToken.Token); err != nil {
			return nil, errors.Wrap(err, "Manager.CreateRefreshToken Delete")
		}
	}

	tokenBytes := make([]byte, 32) // 256 bits
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, errors.Wrap(err, "Manager.CreateRefreshToken rand.Read")
	}

	tokenStr := hex.EncodeToString(tokenBytes)
	if err := c.refreshrepo.Upsert(&RefreshToken{
		Token:    tokenStr,
		UserID:   userID,
		ClientID: clientID,
		TenantID: tenantID,
		Scope:    scope,
		Iat:      NowTimeFunc(),
	}); err != nil {
		return nil, errors.Wrap(err, "Manager.CreateRefreshToken Upsert")
	}

	return &tokenStr, nil
}

func (c *Manager) Introspection(rawToken string) (*TokenIntrospection, error) {
	if strings.TrimSpace(rawToken) == "" {
		return &TokenIntrospection{Active: false}, nil
	}

	// First, parse unverified to extract tenant ID
	unverifiedToken, _, err := jwt.NewParser().ParseUnverified(rawToken, jwt.MapClaims{})
	if err != nil {
		return &TokenIntrospection{Active: false}, err
	}

	unverifiedClaims, ok := unverifiedToken.Claims.(jwt.MapClaims)
	if !ok {
		return &TokenIntrospection{Active: false}, errors.New("error extracting claims")
	}

	tenantID, _ := unverifiedClaims["tenant"].(string)
	signer, err := c.getSignerForTenant(tenantID)
	if err != nil {
		return &TokenIntrospection{Active: false}, err
	}

	// Now parse and verify with tenant-specific signer
	token, err := jwt.Parse(rawToken, signer.GetVerificationKey)

	if err != nil || !token.Valid {
		return &TokenIntrospection{Active: false}, err
	}

	// Convert token claims to your TokenIntrospection struct
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return &TokenIntrospection{Active: false}, errors.New("error extracting claims from token")
	}

	iss, _ := claims["iss"].(string)
	sub, _ := claims["sub"].(string)
	aud, _ := claims["aud"].(string)
	tenant, _ := claims["tenant"].(string)
	iat, _ := claims["iat"].(float64)
	exp, _ := claims["exp"].(float64)
	jti, _ := claims["jti"].(string)

	iatInt := int64(iat)
	expInt := int64(exp)

	var roles []string
	if claimRoles, ok := claims["roles"]; ok {
		roles = interfaceArrayToString(claimRoles.([]interface{}))
	}

	active := true
	if NowTimeFunc().Unix() > expInt {
		active = false
	}

	// Check if token has been revoked
	if jti != "" && c.revokedCache.IsRevoked(jti) {
		active = false
	}

	return &TokenIntrospection{
		Active: active,
		Aud:    &aud,
		Exp:    &expInt,
		Iat:    &iatInt,
		Iss:    &iss,
		Roles:  roles,
		Sub:    &sub,
		Tenant: tenant,
	}, nil
}

func interfaceArrayToString(iArray []interface{}) []string {
	stringSlice := make([]string, 0)
	for _, v := range iArray {
		if s, ok := v.(string); ok {
			stringSlice = append(stringSlice, s)
		}
	}
	return stringSlice
}

func (c *Manager) GenerateTokenResponse(parameters oauth2.TokenRequest, tokenSpecifics TokenSpecifics) (*oauth2.TokenResponse, error) {
	var idToken, accessToken, refreshToken *string

	// Handle refresh token grant
	if parameters.RefreshToken != "" {
		return c.handleRefreshTokenGrant(parameters)
	}

	// Create a User Token
	if strings.TrimSpace(parameters.ClientSecret) == "" && tokenSpecifics.UserEmail != "" {
		user, err := c.userRepo.GetByEmail(tokenSpecifics.UserEmail)
		if err != nil {
			return nil, errors.Wrap(err, "AuthorizationService.generateTokenResponse GetEmail")
		}
		idToken, err = c.CreateIDToken(user, tokenSpecifics.TenantID, parameters.ClientID, tokenSpecifics.Nonce)
		if err != nil {
			return nil, errors.Wrap(err, "AuthorizationService.generateTokenResponse CreateIDToken")
		}
		accessToken, err = c.CreateAccessToken(user, tokenSpecifics.TenantID, parameters.ClientID, tokenSpecifics.Scope)
		if err != nil {
			return nil, errors.Wrap(err, "AuthorizationService.generateTokenResponse CreateAccessToken")
		}
		// Create refresh token if tenant has refresh token expiry configured
		tenant, err := c.getTenant(tokenSpecifics.TenantID)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get tenant")
		}
		if tenant.RefreshTokenExpiry > 0 {
			refreshToken, err = c.CreateRefreshToken(parameters.ClientID, user.ID, tokenSpecifics.TenantID, tokenSpecifics.Scope)
			if err != nil {
				return nil, errors.Wrap(err, "AuthorizationService.generateTokenResponse CreateRefreshToken")
			}
		}
		return &oauth2.TokenResponse{
			AccessToken:  accessToken,
			IdToken:      idToken,
			TokenType:    "bearer",
			ExpiresIn:    int(tenant.AccessTokenExpiry.Seconds()),
			RefreshToken: refreshToken,
			Scope:        tokenSpecifics.Scope,
		}, nil
	} else if strings.TrimSpace(parameters.ClientSecret) != "" { // Create ClientID / Secret token
		var err error
		accessToken, err = c.CreateAccessToken(nil, tokenSpecifics.TenantID, parameters.ClientID, tokenSpecifics.Scope)
		if err != nil {
			return nil, errors.Wrap(err, "AuthorizationService.generateTokenResponse Client CreateAccessToken")
		}
		tenant, err := c.getTenant(tokenSpecifics.TenantID)
		if err != nil {
			return nil, errors.Wrap(err, "failed to get tenant")
		}
		return &oauth2.TokenResponse{
			AccessToken:  accessToken,
			IdToken:      idToken,
			TokenType:    "bearer",
			ExpiresIn:    int(tenant.AccessTokenExpiry.Seconds()),
			RefreshToken: refreshToken,
			Scope:        tokenSpecifics.Scope,
		}, nil
	}

	return nil, errors.New("invalid token request")
}

func (c *Manager) handleRefreshTokenGrant(parameters oauth2.TokenRequest) (*oauth2.TokenResponse, error) {
	// Get the refresh token from storage
	rt, err := c.refreshrepo.Get(parameters.RefreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	// Load tenant for configuration
	tenant, err := c.getTenant(rt.TenantID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get tenant")
	}

	// Check if refresh token has expired using tenant-specific expiry
	if NowTimeFunc().Sub(rt.Iat) > tenant.RefreshTokenExpiry {
		_ = c.refreshrepo.Delete(parameters.RefreshToken)
		return nil, errors.New("refresh token expired")
	}

	// Get the user
	user, err := c.userRepo.GetByID(rt.UserID)
	if err != nil {
		return nil, errors.Wrap(err, "user not found for refresh token")
	}

	// Check if user is blocked or unverified
	if user.Blocked {
		return nil, errors.New("user is blocked")
	}
	if !user.Verified {
		return nil, errors.New("user is not verified")
	}

	// Generate new access token using original tenant and scope
	accessToken, err := c.CreateAccessToken(user, rt.TenantID, rt.ClientID, rt.Scope)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create access token")
	}

	// Generate new ID token
	idToken, err := c.CreateIDToken(user, rt.TenantID, rt.ClientID, "")
	if err != nil {
		return nil, errors.Wrap(err, "failed to create ID token")
	}

	// Rotate refresh token (delete old, create new)
	newRefreshToken, err := c.CreateRefreshToken(rt.ClientID, rt.UserID, rt.TenantID, rt.Scope)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new refresh token")
	}

	return &oauth2.TokenResponse{
		AccessToken:  accessToken,
		IdToken:      idToken,
		TokenType:    "bearer",
		ExpiresIn:    int(tenant.AccessTokenExpiry.Seconds()),
		RefreshToken: newRefreshToken,
	}, nil
}

func (c *Manager) InvalidateRefreshToken(refreshToken string) {
	_ = c.refreshrepo.Delete(refreshToken)
}

// signTokenWithSigner signs JWT claims using the specified signer
func (c *Manager) signTokenWithSigner(claims jwt.MapClaims, signer Signer) (*string, error) {
	signedToken, err := signer.Sign(claims)
	if err != nil {
		return nil, err
	}
	return &signedToken, nil
}

// GetJWKS returns the JSON Web Key Set for public key distribution
// Only works with KeyPairSigner (asymmetric keys)
func (c *Manager) GetJWKS(tenantID string) (*JWKS, error) {
	signer, err := c.getSignerForTenant(tenantID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to get signer for tenant")
	}

	// Check if signer supports JWKS (only asymmetric signers do)
	keyPairSigner, ok := signer.(*KeyPairSigner)
	if !ok {
		return nil, errors.New("JWKS only supported for asymmetric signing (RSA/ECDSA)")
	}

	return keyPairSigner.GetJWKS()
}

// CleanupRevokedTokens removes expired tokens from the revocation cache
func (c *Manager) CleanupRevokedTokens() {
	if c.revokedCache != nil {
		c.revokedCache.Cleanup()
	}
}

// getTenant loads a tenant once
func (c *Manager) getTenant(tenantID string) (*tenants.Tenant, error) {
	if tenantID == "" {
		return nil, errors.New("tenant ID is required")
	}

	if c.tenantRepo == nil {
		return nil, errors.New("tenant repository not configured")
	}

	tenant, err := c.tenantRepo.Get(tenantID)
	if err != nil {
		return nil, errors.Wrapf(err, "tenant %s not found", tenantID)
	}

	return tenant, nil
}

// getSignerForTenant returns the signer for a specific tenant
func (c *Manager) getSignerForTenant(tenantID string) (Signer, error) {
	if tenantID == "" {
		return nil, errors.New("tenant ID is required")
	}

	// Check if tenant has a specific signer in the cache
	if signer, exists := c.tenantSigners[tenantID]; exists {
		return signer, nil
	}

	// Load tenant and build signer from key material
	tenant, err := c.getTenant(tenantID)
	if err != nil {
		return nil, err
	}

	return c.getSignerFromTenant(tenant)
}

// getSignerFromTenant creates and caches a signer from a tenant object
func (c *Manager) getSignerFromTenant(tenant *tenants.Tenant) (Signer, error) {
	// Check cache first
	if signer, exists := c.tenantSigners[tenant.ID]; exists {
		return signer, nil
	}

	// Try to create a signer from the tenant's key material
	signer, err := createSignerFromTenant(tenant)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to create signer for tenant %s", tenant.ID)
	}

	// Cache it for future use
	c.tenantSigners[tenant.ID] = signer
	return signer, nil
}

// RegisterTenantSigner allows registering a custom signer for a specific tenant
// This enables per-tenant key rotation and isolation
func (c *Manager) RegisterTenantSigner(tenantID string, signer Signer) {
	if c.tenantSigners == nil {
		c.tenantSigners = make(map[string]Signer)
	}
	c.tenantSigners[tenantID] = signer
}

// getCombinedRoles returns a combined list of system roles and tenant-specific roles
func (c *Manager) getCombinedRoles(user *users.User, tenantID string) []string {
	roles := make([]string, 0)

	// Add system roles
	for _, role := range user.SystemRoles {
		roles = append(roles, string(role))
	}

	// Add tenant-specific roles if tenantID is provided
	if tenantID != "" {
		tenantRoles := user.GetRolesForTenant(tenantID)
		for _, role := range tenantRoles {
			roles = append(roles, string(role))
		}
	}

	return roles
}

// RevokeAccessToken revokes an access token by its JTI
func (c *Manager) RevokeAccessToken(rawToken string) error {
	// First, parse unverified to extract tenant ID
	unverifiedToken, _, err := jwt.NewParser().ParseUnverified(rawToken, jwt.MapClaims{})
	if err != nil {
		return errors.Wrap(err, "failed to parse token")
	}

	unverifiedClaims, ok := unverifiedToken.Claims.(jwt.MapClaims)
	if !ok {
		return errors.New("error extracting claims")
	}

	tenantID, _ := unverifiedClaims["tenant"].(string)
	signer, err := c.getSignerForTenant(tenantID)
	if err != nil {
		return errors.Wrap(err, "failed to get signer for tenant")
	}

	// Parse and verify with tenant-specific signer
	token, err := jwt.Parse(rawToken, signer.GetVerificationKey)

	if err != nil || !token.Valid {
		return errors.Wrap(err, "invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return errors.New("error extracting claims from token")
	}

	jti, ok := claims["jti"].(string)
	if !ok || jti == "" {
		return errors.New("token missing jti claim")
	}

	exp, ok := claims["exp"].(float64)
	if !ok {
		return errors.New("token missing exp claim")
	}

	expTime := time.Unix(int64(exp), 0)
	return c.revokedCache.Add(jti, expTime)
}

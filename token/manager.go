package token

import (
	"crypto/rand"
	"encoding/hex"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jrsteele09/go-auth-server/users"
	"github.com/pkg/errors"
)

// TokenResponse represents the response from an OAuth2 token request.
type TokenResponse struct {
	AccessToken  *string `json:"access_token,omitempty"`
	IdToken      *string `json:"id_token,omitempty"`
	TokenType    string  `json:"token_type,omitempty"`
	ExpiresIn    int     `json:"expires_in,omitempty"`
	RefreshToken *string `json:"refresh_token,omitempty"`
	Scope        string  `json:"scope,omitempty"`
}

type RefreshToken struct {
	Token    string
	UserID   string
	ClientID string
	Iat      time.Time
}

// TokenParameters holds parameters for the OAuth2 token request.
type TokenParameters struct {
	ClientID     string
	ClientSecret string
	Code         string
	CodeVerifier string
	RefreshToken string
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
	signer             Signer // Token signing and verification
	issuer             string
	audience           string
	createRefreshToken bool
	refreshrepo        RefreshTokenRepo
	userRepo           users.UserRepo    // Repository for user data
	revokedCache       RevokedTokenCache // Cache for revoked tokens
	accessTokenExpiry  time.Duration
	idTokenExpiry      time.Duration
	refreshTokenExpiry time.Duration
	nowFunc            func() time.Time
}

type ManagerOption func(*Manager)

func WithTokenExpiry(accessTokenExpiry time.Duration, idTokenExpiry time.Duration, refreshTokenExpiry time.Duration) ManagerOption {
	return func(m *Manager) {
		m.accessTokenExpiry = accessTokenExpiry
		m.idTokenExpiry = accessTokenExpiry
		m.refreshTokenExpiry = refreshTokenExpiry
		m.createRefreshToken = refreshTokenExpiry > 0
	}
}

func WithNowFunc(now func() time.Time) ManagerOption {
	return func(m *Manager) {
		m.nowFunc = now
	}
}

func WithIssuer(issuer string) ManagerOption {
	return func(m *Manager) {
		m.issuer = issuer
	}
}

func WithAudience(audience string) ManagerOption {
	return func(m *Manager) {
		m.audience = audience
	}
}

func WithRevokedTokenCache(cache RevokedTokenCache) ManagerOption {
	return func(m *Manager) {
		m.revokedCache = cache
	}
}

func New(repo RefreshTokenRepo, userRepo users.UserRepo, signer Signer, options ...ManagerOption) *Manager {
	m := &Manager{
		refreshrepo:  repo,
		userRepo:     userRepo,
		signer:       signer,
		revokedCache: NewInMemoryRevokedTokenCache(), // Default implementation
	}

	for _, opt := range options {
		opt(m)
	}

	if m.accessTokenExpiry == 0 {
		m.accessTokenExpiry = time.Minute
	}
	if m.idTokenExpiry == 0 {
		m.idTokenExpiry = time.Hour
	}
	if m.refreshTokenExpiry == 0 {
		m.refreshTokenExpiry = time.Minute * 10
	}

	if m.nowFunc == nil {
		m.nowFunc = time.Now
	}
	return m
}

func (c *Manager) CreateIDToken(user *users.User, tenantID, clientID, nonce string) (*string, error) {
	claims := jwt.MapClaims{
		"iss":   c.issuer,
		"sub":   user.ID,
		"aud":   clientID,
		"email": user.Email,
		"name":  user.FirstName + " " + user.LastName,
		"roles": user.Roles,
		"iat":   int64(c.nowFunc().Unix()),
		"exp":   int64(c.nowFunc().Add(c.idTokenExpiry).Unix()),
		"jti":   uuid.New().String(),
	}

	if nonce != "" {
		claims["nonce"] = nonce
	}

	// Sign the token
	return c.signToken(claims)
}

func (c *Manager) CreateAccessToken(user *users.User, tenantID, clientID string) (*string, error) {
	claims := jwt.MapClaims{
		"iss":    c.issuer,   // The issuer of the token
		"sub":    clientID,   // The subject, in this case the client ID
		"aud":    c.audience, // The audience for which the token is intended
		"tenant": tenantID,
		"iat":    int64(c.nowFunc().Unix()),                          // Issued At: the time at which the token was issued
		"exp":    int64(c.nowFunc().Add(c.accessTokenExpiry).Unix()), // Expiry: when the token will expire
		"jti":    uuid.New().String(),                                // Unique token ID for revocation
	}

	if user != nil {
		claims["roles"] = user.Roles
		claims["sub"] = user.ID
	}

	// Sign the token
	return c.signToken(claims)
}

func (c *Manager) CreateRefreshToken(clientID, userID string) (*string, error) {
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
		Iat:      c.nowFunc(),
	}); err != nil {
		return nil, errors.Wrap(err, "Manager.CreateRefreshToken Upsert")
	}

	return &tokenStr, nil
}

func (c *Manager) Introspection(rawToken string) (*TokenIntrospection, error) {
	if strings.TrimSpace(rawToken) == "" {
		return &TokenIntrospection{Active: false}, nil
	}

	// Parse the token
	token, err := jwt.Parse(rawToken, c.signer.GetVerificationKey)

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
	if c.nowFunc().Unix() > expInt {
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

func (c *Manager) GenerateTokenResponse(parameters TokenParameters, tokenSpecifics TokenSpecifics) (*TokenResponse, error) {
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
		accessToken, err = c.CreateAccessToken(user, tokenSpecifics.TenantID, parameters.ClientID)
		if err != nil {
			return nil, errors.Wrap(err, "AuthorizationService.generateTokenResponse CreateAccessToken")
		}
		if c.createRefreshToken {
			var err error
			refreshToken, err = c.CreateRefreshToken(parameters.ClientID, user.ID)
			if err != nil {
				return nil, errors.Wrap(err, "AuthorizationService.generateTokenResponse CreateRefreshToken")
			}
		}
	} else if strings.TrimSpace(parameters.ClientSecret) != "" { // Create ClientID / Secret token
		var err error
		accessToken, err = c.CreateAccessToken(nil, tokenSpecifics.TenantID, parameters.ClientID)
		if err != nil {
			return nil, errors.Wrap(err, "AuthorizationService.generateTokenResponse Client CreateAccessToken")
		}
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		IdToken:      idToken,
		TokenType:    "bearer",
		ExpiresIn:    int(c.accessTokenExpiry.Seconds()),
		RefreshToken: refreshToken,
		Scope:        tokenSpecifics.Scope,
	}, nil
}

func (c *Manager) handleRefreshTokenGrant(parameters TokenParameters) (*TokenResponse, error) {
	// Get the refresh token from storage
	rt, err := c.refreshrepo.Get(parameters.RefreshToken)
	if err != nil {
		return nil, errors.New("invalid refresh token")
	}

	// Check if refresh token has expired
	if c.nowFunc().Sub(rt.Iat) > c.refreshTokenExpiry {
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

	// Generate new access token
	accessToken, err := c.CreateAccessToken(user, "", rt.ClientID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create access token")
	}

	// Generate new ID token
	idToken, err := c.CreateIDToken(user, "", rt.ClientID, "")
	if err != nil {
		return nil, errors.Wrap(err, "failed to create ID token")
	}

	// Rotate refresh token (delete old, create new)
	newRefreshToken, err := c.CreateRefreshToken(rt.ClientID, rt.UserID)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create new refresh token")
	}

	return &TokenResponse{
		AccessToken:  accessToken,
		IdToken:      idToken,
		TokenType:    "bearer",
		ExpiresIn:    int(c.accessTokenExpiry.Seconds()),
		RefreshToken: newRefreshToken,
	}, nil
}

func (c *Manager) InvalidateRefreshToken(refreshToken string) {
	_ = c.refreshrepo.Delete(refreshToken)
}

// signToken signs JWT claims using the configured signer
func (c *Manager) signToken(claims jwt.MapClaims) (*string, error) {
	signedToken, err := c.signer.Sign(claims)
	if err != nil {
		return nil, err
	}
	return &signedToken, nil
}

// GetJWKS returns the JSON Web Key Set for public key distribution
// Only works with AsymmetricSigner
func (c *Manager) GetJWKS() (*JWKS, error) {
	// Check if signer supports JWKS (only asymmetric signers do)
	asymSigner, ok := c.signer.(*AsymmetricSigner)
	if !ok {
		return nil, errors.New("JWKS only supported for asymmetric signing (RSA/ECDSA)")
	}

	return asymSigner.GetJWKS()
}

// CleanupRevokedTokens removes expired tokens from the revocation cache
func (c *Manager) CleanupRevokedTokens() {
	if c.revokedCache != nil {
		c.revokedCache.Cleanup()
	}
}

// RevokeAccessToken revokes an access token by its JTI
func (c *Manager) RevokeAccessToken(rawToken string) error {
	// Parse the token
	token, err := jwt.Parse(rawToken, c.signer.GetVerificationKey)

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

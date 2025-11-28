package jwt

import (
	"fmt"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jrsteele09/go-auth-server/internal/config"
	"github.com/jrsteele09/go-auth-server/tenants"
	"github.com/jrsteele09/go-auth-server/token/keys"
	"github.com/jrsteele09/go-auth-server/users"
)

// NowTimeFunc returns the current time. It can be overridden in tests.
var NowTimeFunc = time.Now

// Creator handles JWT token creation (ID tokens and access tokens)
type Creator struct {
	config config.OAuthConfig
}

// NewCreator creates a new JWT creator
func NewCreator(cfg config.OAuthConfig) *Creator {
	return &Creator{
		config: cfg,
	}
}

// CreateIDToken creates an OpenID Connect ID token
func (c *Creator) CreateIDToken(user *users.User, tenant *tenants.Tenant, clientID, nonce string, signer keys.Signer) (*string, error) {
	// ID Token contains identity claims only (OpenID Connect spec)
	// Authorization data like roles belongs in the access token
	claims := jwtlib.MapClaims{
		"iss":    tenant.Config.Issuer,
		"sub":    user.ID,
		"aud":    clientID,
		"email":  user.Email,
		"name":   user.FirstName + " " + user.LastName,
		"tenant": tenant.ID,
		"iat":    int64(NowTimeFunc().Unix()),
		"exp":    int64(NowTimeFunc().Add(tenant.Config.GetIDTokenExpiry(c.config.GetDefaultIDTokenExpiry())).Unix()),
		"jti":    uuid.New().String(),
	}

	if nonce != "" {
		claims["nonce"] = nonce
	}

	// Sign the token with tenant-specific or default signer
	return c.signTokenWithSigner(claims, signer)
}

// CreateAccessToken creates an OAuth2 access token
func (c *Creator) CreateAccessToken(user *users.User, tenant *tenants.Tenant, clientID, scope string, signer keys.Signer) (*string, error) {
	claims := jwtlib.MapClaims{
		"iss":       tenant.Config.Issuer,                                                                                        // The issuer of the token (tenant-specific)
		"aud":       tenant.Config.Audience,                                                                                      // The audience for which the token is intended (tenant-specific)
		"client_id": clientID,                                                                                                    // The OAuth2 client that requested the token
		"scope":     scope,                                                                                                       // OAuth2 scopes granted to this token
		"tenant":    tenant.ID,                                                                                                   // Explicit tenant ID for multi-tenant context
		"iat":       int64(NowTimeFunc().Unix()),                                                                                 // Issued At: the time at which the token was issued
		"exp":       int64(NowTimeFunc().Add(tenant.Config.GetAccessTokenExpiry(c.config.GetDefaultAccessTokenExpiry())).Unix()), // Expiry: when the token will expire
		"jti":       uuid.New().String(),                                                                                         // Unique token ID for revocation
	}

	if user != nil {
		// User-delegated access token (authorization code flow)
		claims["sub"] = user.ID
		claims["roles"] = getCombinedRoles(user, tenant.ID)
		claims["token_type"] = "user"
	} else {
		// Client credentials token (machine-to-machine)
		claims["sub"] = clientID
		claims["token_type"] = "client"
	}

	// Sign the token with tenant-specific signer
	return c.signTokenWithSigner(claims, signer)
}

// signTokenWithSigner signs JWT claims using the specified signer
func (c *Creator) signTokenWithSigner(claims jwtlib.MapClaims, signer keys.Signer) (*string, error) {
	signedToken, err := signer.Sign(claims)
	if err != nil {
		return nil, fmt.Errorf("failed to sign JWT token: %w", err)
	}
	return &signedToken, nil
}

// getCombinedRoles returns a combined list of system roles and tenant-specific roles
func getCombinedRoles(user *users.User, tenantID string) []string {
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

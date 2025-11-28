package jwt

import (
	"errors"
	"fmt"
	"strings"
	"time"

	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/jrsteele09/go-auth-server/internal/utils"
	"github.com/jrsteele09/go-auth-server/tenants"
	"github.com/jrsteele09/go-auth-server/token/keys"
)

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

// RevokedChecker is an interface for checking if a token has been revoked
type RevokedChecker interface {
	IsRevoked(jti string) bool
}

// Inspector handles JWT token introspection and validation
type Inspector struct {
	tenantRepo     tenants.Repo
	revokedChecker RevokedChecker
}

// NewInspector creates a new JWT inspector
func NewInspector(tenantRepo tenants.Repo, revokedChecker RevokedChecker) *Inspector {
	return &Inspector{
		tenantRepo:     tenantRepo,
		revokedChecker: revokedChecker,
	}
}

// Introspect validates and extracts information from a JWT token
func (i *Inspector) Introspect(rawToken string, signerProvider func(*tenants.Tenant) (keys.Signer, error)) (*TokenIntrospection, error) {
	if strings.TrimSpace(rawToken) == "" {
		return &TokenIntrospection{Active: false}, nil
	}

	// First, parse unverified to extract tenant ID
	unverifiedToken, _, err := jwtlib.NewParser().ParseUnverified(rawToken, jwtlib.MapClaims{})
	if err != nil {
		return &TokenIntrospection{Active: false}, err
	}

	unverifiedClaims, ok := unverifiedToken.Claims.(jwtlib.MapClaims)
	if !ok {
		return &TokenIntrospection{Active: false}, errors.New("error extracting claims")
	}

	tenantID, _ := unverifiedClaims["tenant"].(string)
	tenant, err := i.tenantRepo.Get(tenantID)
	if err != nil {
		return &TokenIntrospection{Active: false}, err
	}

	signer, err := signerProvider(tenant)
	if err != nil {
		return &TokenIntrospection{Active: false}, err
	}

	// Now parse and verify with tenant-specific signer
	token, err := jwtlib.ParseWithClaims(rawToken, jwtlib.MapClaims{}, signer.GetVerificationKey)

	if err != nil || !token.Valid {
		return &TokenIntrospection{Active: false}, err
	}

	// Convert token claims to TokenIntrospection struct
	claims, ok := token.Claims.(jwtlib.MapClaims)
	if !ok {
		return &TokenIntrospection{Active: false}, errors.New("error extracting claims from token")
	}

	iss, _ := claims["iss"].(string)
	sub, _ := claims["sub"].(string)
	aud, _ := claims["aud"].(string)
	tenantClaim, _ := claims["tenant"].(string)
	iat, _ := claims["iat"].(float64)
	exp, _ := claims["exp"].(float64)
	jti, _ := claims["jti"].(string)

	iatInt := int64(iat)
	expInt := int64(exp)

	var roles []string
	if claimRoles, ok := claims["roles"]; ok {
		roles = utils.ToStringSlice(claimRoles.([]any))
	}

	active := true
	if NowTimeFunc().Unix() > expInt {
		active = false
	}

	// Check if token has been revoked
	if jti != "" && i.revokedChecker != nil && i.revokedChecker.IsRevoked(jti) {
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
		Tenant: tenantClaim,
	}, nil
}

// RevokeToken revokes an access token by its JTI
func (i *Inspector) ParseAndExtractJTI(rawToken string, signerProvider func(*tenants.Tenant) (keys.Signer, error)) (jti string, exp time.Time, err error) {
	// First, parse unverified to extract tenant ID
	unverifiedToken, _, err := jwtlib.NewParser().ParseUnverified(rawToken, jwtlib.MapClaims{})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to parse token: %w", err)
	}

	unverifiedClaims, ok := unverifiedToken.Claims.(jwtlib.MapClaims)
	if !ok {
		return "", time.Time{}, errors.New("error extracting claims")
	}

	tenantID, _ := unverifiedClaims["tenant"].(string)
	tenant, err := i.tenantRepo.Get(tenantID)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to get tenant: %w", err)
	}

	signer, err := signerProvider(tenant)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to get signer for tenant: %w", err)
	}

	// Parse and verify with tenant-specific signer
	token, err := jwtlib.ParseWithClaims(rawToken, jwtlib.MapClaims{}, signer.GetVerificationKey)

	if err != nil || !token.Valid {
		return "", time.Time{}, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(jwtlib.MapClaims)
	if !ok {
		return "", time.Time{}, errors.New("error extracting claims from token")
	}

	jtiClaim, ok := claims["jti"].(string)
	if !ok || jtiClaim == "" {
		return "", time.Time{}, errors.New("token missing jti claim")
	}

	expClaim, ok := claims["exp"].(float64)
	if !ok {
		return "", time.Time{}, errors.New("token missing exp claim")
	}

	expTime := time.Unix(int64(expClaim), 0)
	return jtiClaim, expTime, nil
}

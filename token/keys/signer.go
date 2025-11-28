package keys

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jrsteele09/go-auth-server/tenants"
)

// Signer is an interface for signing and verifying JWT tokens
type Signer interface {
	// Sign creates a signed JWT token from claims
	Sign(claims jwt.MapClaims) (string, error)

	// Verify parses and validates a JWT token, returning the signing key for verification
	GetVerificationKey(token *jwt.Token) (any, error)

	// GetSigningMethod returns the JWT signing method used
	GetSigningMethod() jwt.SigningMethod
}

// KeyPairSigner implements Signer using RSA with RS256
type KeyPairSigner struct {
	keyPair *KeyPair
}

// NewKeyPairSigner creates a new key pair signer with the given key pair
func NewKeyPairSigner(keyPair *KeyPair) *KeyPairSigner {
	return &KeyPairSigner{
		keyPair: keyPair,
	}
}

func (a *KeyPairSigner) Sign(claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(a.keyPair.GetSigningMethod(), claims)
	token.Header["kid"] = a.keyPair.KeyID

	signedToken, err := token.SignedString(a.keyPair.PrivateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign token with asymmetric key: %w", err)
	}
	return signedToken, nil
}

func (a *KeyPairSigner) GetVerificationKey(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	return a.keyPair.PublicKey, nil
}

func (a *KeyPairSigner) GetSigningMethod() jwt.SigningMethod {
	return a.keyPair.GetSigningMethod()
}

// GetJWKS returns the JSON Web Key Set (only for asymmetric signers)
func (a *KeyPairSigner) GetJWKS() (*JWKS, error) {
	jwk, err := a.keyPair.ToJWK()
	if err != nil {
		return nil, fmt.Errorf("failed to convert key to JWK: %w", err)
	}

	return &JWKS{
		Keys: []JWK{*jwk},
	}, nil
}

// CreateSignerFromTenant reconstructs a signer from the tenant's stored key material
func CreateSignerFromTenant(tenant *tenants.Tenant) (Signer, error) {
	if !tenant.Keys.HasKeys() {
		return nil, fmt.Errorf("tenant %s has no key pair", tenant.ID)
	}
	keyPair, err := LoadKeyPairFromPEM(tenant.Keys.KeyID, tenant.Keys.PrivateKeyPEM, tenant.Keys.PublicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load key pair for tenant %s: %w", tenant.ID, err)
	}
	return NewKeyPairSigner(keyPair), nil
}

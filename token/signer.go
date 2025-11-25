package token

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/pkg/errors"
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

// HMACsigner implements Signer using symmetric HMAC-SHA256
type HMACsigner struct {
	secret []byte
}

// NewHMACSigner creates a new HMAC signer with the given secret
func NewHMACSigner(secret string) *HMACsigner {
	return &HMACsigner{
		secret: []byte(secret),
	}
}

func (h *HMACsigner) Sign(claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(h.secret)
	if err != nil {
		return "", errors.Wrap(err, "failed to sign token with HMAC")
	}
	return signedToken, nil
}

func (h *HMACsigner) GetVerificationKey(token *jwt.Token) (interface{}, error) {
	if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
		return nil, errors.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
	return h.secret, nil
}

func (h *HMACsigner) GetSigningMethod() jwt.SigningMethod {
	return jwt.SigningMethodHS256
}

// KeyPairSigner implements Signer using RSA or ECDSA
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
		return "", errors.Wrap(err, "failed to sign token with asymmetric key")
	}
	return signedToken, nil
}

func (a *KeyPairSigner) GetVerificationKey(token *jwt.Token) (interface{}, error) {
	switch token.Method.(type) {
	case *jwt.SigningMethodRSA, *jwt.SigningMethodECDSA:
		return a.keyPair.PublicKey, nil
	default:
		return nil, errors.Errorf("unexpected signing method: %v", token.Header["alg"])
	}
}

func (a *KeyPairSigner) GetSigningMethod() jwt.SigningMethod {
	return a.keyPair.GetSigningMethod()
}

// GetJWKS returns the JSON Web Key Set (only for asymmetric signers)
func (a *KeyPairSigner) GetJWKS() (*JWKS, error) {
	jwk, err := a.keyPair.ToJWK()
	if err != nil {
		return nil, errors.Wrap(err, "failed to convert key to JWK")
	}

	return &JWKS{
		Keys: []JWK{*jwk},
	}, nil
}

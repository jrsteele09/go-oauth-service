package token

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pkg/errors"
)

// KeyPair represents a public/private key pair for signing tokens
type KeyPair struct {
	KeyID      string
	PrivateKey crypto.PrivateKey
	PublicKey  crypto.PublicKey
	Algorithm  string // RS256, RS384, RS512, ES256, ES384, ES512
}

// JWKS represents a JSON Web Key Set
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWK represents a JSON Web Key
type JWK struct {
	Kty string `json:"kty"`           // Key type (RSA, EC)
	Use string `json:"use,omitempty"` // sig or enc
	Kid string `json:"kid,omitempty"` // Key ID
	Alg string `json:"alg,omitempty"` // Algorithm

	// RSA specific
	N string `json:"n,omitempty"` // Modulus
	E string `json:"e,omitempty"` // Exponent

	// EC specific
	Crv string `json:"crv,omitempty"` // Curve
	X   string `json:"x,omitempty"`   // X coordinate
	Y   string `json:"y,omitempty"`   // Y coordinate
}

// GenerateRSAKeyPair generates a new RSA key pair for RS256 signing
func GenerateRSAKeyPair(keyID string, bits int) (*KeyPair, error) {
	if bits < 2048 {
		bits = 2048
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate RSA key")
	}

	return &KeyPair{
		KeyID:      keyID,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		Algorithm:  "RS256",
	}, nil
}

// GenerateECDSAKeyPair generates a new ECDSA key pair for ES256 signing
func GenerateECDSAKeyPair(keyID string) (*KeyPair, error) {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, errors.Wrap(err, "failed to generate ECDSA key")
	}

	return &KeyPair{
		KeyID:      keyID,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		Algorithm:  "ES256",
	}, nil
}

// GetSigningMethod returns the JWT signing method for this key pair
func (kp *KeyPair) GetSigningMethod() jwt.SigningMethod {
	switch kp.Algorithm {
	case "RS256":
		return jwt.SigningMethodRS256
	case "RS384":
		return jwt.SigningMethodRS384
	case "RS512":
		return jwt.SigningMethodRS512
	case "ES256":
		return jwt.SigningMethodES256
	case "ES384":
		return jwt.SigningMethodES384
	case "ES512":
		return jwt.SigningMethodES512
	default:
		return jwt.SigningMethodRS256
	}
}

// ExportPublicKeyPEM exports the public key as PEM
func (kp *KeyPair) ExportPublicKeyPEM() (string, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(kp.PublicKey)
	if err != nil {
		return "", errors.Wrap(err, "failed to marshal public key")
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return string(pubKeyPEM), nil
}

// ExportPrivateKeyPEM exports the private key as PEM
func (kp *KeyPair) ExportPrivateKeyPEM() (string, error) {
	var privateKeyBytes []byte
	var err error
	var blockType string

	switch key := kp.PrivateKey.(type) {
	case *rsa.PrivateKey:
		privateKeyBytes = x509.MarshalPKCS1PrivateKey(key)
		blockType = "RSA PRIVATE KEY"
	case *ecdsa.PrivateKey:
		privateKeyBytes, err = x509.MarshalECPrivateKey(key)
		if err != nil {
			return "", errors.Wrap(err, "failed to marshal ECDSA private key")
		}
		blockType = "EC PRIVATE KEY"
	default:
		return "", errors.New("unsupported private key type")
	}

	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  blockType,
		Bytes: privateKeyBytes,
	})

	return string(privateKeyPEM), nil
}

// ToJWK converts the key pair's public key to JWK format
func (kp *KeyPair) ToJWK() (*JWK, error) {
	jwk := &JWK{
		Kid: kp.KeyID,
		Use: "sig",
		Alg: kp.Algorithm,
	}

	switch pubKey := kp.PublicKey.(type) {
	case *rsa.PublicKey:
		jwk.Kty = "RSA"
		jwk.N = base64.RawURLEncoding.EncodeToString(pubKey.N.Bytes())
		jwk.E = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pubKey.E)).Bytes())

	case *ecdsa.PublicKey:
		jwk.Kty = "EC"
		jwk.Crv = "P-256" // For ES256
		jwk.X = base64.RawURLEncoding.EncodeToString(pubKey.X.Bytes())
		jwk.Y = base64.RawURLEncoding.EncodeToString(pubKey.Y.Bytes())

	default:
		return nil, errors.New("unsupported public key type")
	}

	return jwk, nil
}

// LoadRSAPrivateKeyFromPEM loads an RSA private key from PEM format
func LoadRSAPrivateKeyFromPEM(pemData string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse RSA private key")
	}

	return privateKey, nil
}

// LoadECDSAPrivateKeyFromPEM loads an ECDSA private key from PEM format
func LoadECDSAPrivateKeyFromPEM(pemData string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}

	privateKey, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, errors.Wrap(err, "failed to parse ECDSA private key")
	}

	return privateKey, nil
}

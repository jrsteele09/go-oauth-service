package keys

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"

	"github.com/golang-jwt/jwt/v5"
	"github.com/jrsteele09/go-auth-server/tenants"
)

// JWT algorithms (string values used in JWKs and headers)
const RS256 = "RS256"

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
	N   string `json:"n,omitempty"`   // Modulus
	E   string `json:"e,omitempty"`   // Exponent
}

// GenerateRSAKeyPair generates a new RSA key pair for RS256 signing
func GenerateRSAKeyPair(keyID string, bits int) (*KeyPair, error) {
	if bits < 2048 {
		bits = 2048
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	return &KeyPair{
		KeyID:      keyID,
		PrivateKey: privateKey,
		PublicKey:  &privateKey.PublicKey,
		Algorithm:  RS256,
	}, nil
}

// GetSigningMethod returns the JWT signing method for this key pair
func (kp *KeyPair) GetSigningMethod() jwt.SigningMethod {
	return jwt.SigningMethodRS256
}

// ExportPublicKeyPEM exports the public key as PEM
func (kp *KeyPair) ExportPublicKeyPEM() (string, error) {
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(kp.PublicKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	return string(pubKeyPEM), nil
}

// ExportPrivateKeyPEM exports the RSA private key as PEM
func (kp *KeyPair) ExportPrivateKeyPEM() (string, error) {
	rsaKey, ok := kp.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return "", fmt.Errorf("private key is not RSA")
	}

	privateKeyBytes := x509.MarshalPKCS1PrivateKey(rsaKey)
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
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

	default:
		return nil, fmt.Errorf("unsupported public key type")
	}

	return jwk, nil
}

// LoadRSAPrivateKeyFromPEM loads an RSA private key from PEM format
func LoadRSAPrivateKeyFromPEM(pemData string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse RSA private key: %w", err)
	}

	return privKey, nil
}

// LoadKeyPairFromPEM loads a key pair from PEM-encoded strings
func LoadKeyPairFromPEM(keyID, privateKeyPEM, publicKeyPEM string) (*KeyPair, error) {
	var privateKey crypto.PrivateKey
	var publicKey crypto.PublicKey
	var err error

	privateKey, err = LoadRSAPrivateKeyFromPEM(privateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to load RSA private key: %w", err)
	}
	rsaPrivKey := privateKey.(*rsa.PrivateKey)
	publicKey = &rsaPrivKey.PublicKey

	return &KeyPair{
		KeyID:      keyID,
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		Algorithm:  RS256,
	}, nil
}

// GenerateKeysForTenant generates RSA-2048 keys and stores them in the tenant.
// This only modifies the tenant struct, does not return a signer.
func GenerateKeysForTenant(tenant *tenants.Tenant) error {
	keyPair, err := GenerateRSAKeyPair(tenant.Keys.KeyID, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RS256 key pair: %w", err)
	}

	privatePEM, err := keyPair.ExportPrivateKeyPEM()
	if err != nil {
		return fmt.Errorf("failed to export private key: %w", err)
	}

	publicPEM, err := keyPair.ExportPublicKeyPEM()
	if err != nil {
		return fmt.Errorf("failed to export public key: %w", err)
	}

	tenant.Keys.PrivateKeyPEM = privatePEM
	tenant.Keys.PublicKeyPEM = publicPEM
	return nil
}

package token

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/jrsteele09/go-auth-server/tenants"
)

// GenerateSignerForTenant creates a new signer based on the tenant's SignerType
// and stores the key material in the tenant struct
func GenerateSignerForTenant(tenant *tenants.Tenant) (Signer, error) {
	switch tenant.SignerType {
	case tenants.SignerTypeHMAC:
		// Generate a random secret for HMAC
		secret := make([]byte, 32) // 256 bits
		if _, err := rand.Read(secret); err != nil {
			return nil, fmt.Errorf("failed to generate HMAC secret: %w", err)
		}
		secretStr := hex.EncodeToString(secret)
		tenant.HMACSecret = secretStr
		return NewHMACSigner(secretStr), nil

	case tenants.SignerTypeRS256:
		keyPair, err := GenerateRSAKeyPair(tenant.KeyID, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RS256 key pair: %w", err)
		}
		if err := storeKeyPairInTenant(tenant, keyPair); err != nil {
			return nil, err
		}
		return NewKeyPairSigner(keyPair), nil

	case tenants.SignerTypeRS384:
		keyPair, err := GenerateRSAKeyPair(tenant.KeyID, 3072)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RS384 key pair: %w", err)
		}
		if err := storeKeyPairInTenant(tenant, keyPair); err != nil {
			return nil, err
		}
		return NewKeyPairSigner(keyPair), nil

	case tenants.SignerTypeRS512:
		keyPair, err := GenerateRSAKeyPair(tenant.KeyID, 4096)
		if err != nil {
			return nil, fmt.Errorf("failed to generate RS512 key pair: %w", err)
		}
		if err := storeKeyPairInTenant(tenant, keyPair); err != nil {
			return nil, err
		}
		return NewKeyPairSigner(keyPair), nil

	case tenants.SignerTypeES256:
		keyPair, err := GenerateECDSAKeyPair(tenant.KeyID, "ES256")
		if err != nil {
			return nil, fmt.Errorf("failed to generate ES256 key pair: %w", err)
		}
		if err := storeKeyPairInTenant(tenant, keyPair); err != nil {
			return nil, err
		}
		return NewKeyPairSigner(keyPair), nil

	case tenants.SignerTypeES384:
		keyPair, err := GenerateECDSAKeyPair(tenant.KeyID, "ES384")
		if err != nil {
			return nil, fmt.Errorf("failed to generate ES384 key pair: %w", err)
		}
		if err := storeKeyPairInTenant(tenant, keyPair); err != nil {
			return nil, err
		}
		return NewKeyPairSigner(keyPair), nil

	case tenants.SignerTypeES512:
		keyPair, err := GenerateECDSAKeyPair(tenant.KeyID, "ES512")
		if err != nil {
			return nil, fmt.Errorf("failed to generate ES512 key pair: %w", err)
		}
		if err := storeKeyPairInTenant(tenant, keyPair); err != nil {
			return nil, err
		}
		return NewKeyPairSigner(keyPair), nil

	default:
		return nil, fmt.Errorf("unsupported signer type: %s", tenant.SignerType)
	}
}

// createSignerFromTenant reconstructs a signer from the tenant's stored key material
func createSignerFromTenant(tenant *tenants.Tenant) (Signer, error) {
	switch tenant.SignerType {
	case tenants.SignerTypeHMAC:
		if tenant.HMACSecret == "" {
			return nil, fmt.Errorf("tenant %s has no HMAC secret", tenant.ID)
		}
		return NewHMACSigner(tenant.HMACSecret), nil

	case tenants.SignerTypeRS256, tenants.SignerTypeRS384, tenants.SignerTypeRS512,
		tenants.SignerTypeES256, tenants.SignerTypeES384, tenants.SignerTypeES512:
		if tenant.PrivateKeyPEM == "" || tenant.PublicKeyPEM == "" {
			return nil, fmt.Errorf("tenant %s has no key pair", tenant.ID)
		}
		keyPair, err := LoadKeyPairFromPEM(tenant.KeyID, tenant.PrivateKeyPEM, tenant.PublicKeyPEM, string(tenant.SignerType))
		if err != nil {
			return nil, fmt.Errorf("failed to load key pair for tenant %s: %w", tenant.ID, err)
		}
		return NewKeyPairSigner(keyPair), nil

	default:
		return nil, fmt.Errorf("unsupported signer type: %s", tenant.SignerType)
	}
}

// storeKeyPairInTenant converts a KeyPair to PEM format and stores it in the tenant
func storeKeyPairInTenant(tenant *tenants.Tenant, keyPair *KeyPair) error {
	privatePEM, err := keyPair.ExportPrivateKeyPEM()
	if err != nil {
		return fmt.Errorf("failed to export private key: %w", err)
	}

	publicPEM, err := keyPair.ExportPublicKeyPEM()
	if err != nil {
		return fmt.Errorf("failed to export public key: %w", err)
	}

	tenant.PrivateKeyPEM = privatePEM
	tenant.PublicKeyPEM = publicPEM
	return nil
}

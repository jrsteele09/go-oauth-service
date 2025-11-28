package refresh

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/jrsteele09/go-auth-server/internal/config"
)

// NowTimeFunc returns the current time. It can be overridden in tests.
var NowTimeFunc = time.Now

// Manager handles refresh token creation, validation, and rotation
type Manager struct {
	repo   Repo
	config config.OAuthConfig
}

// NewManager creates a new refresh token manager
func NewManager(repo Repo, cfg config.OAuthConfig) *Manager {
	return &Manager{
		repo:   repo,
		config: cfg,
	}
}

// Create generates a new refresh token and stores it
func (m *Manager) Create(clientID, userID, tenantID, scope string) (*string, error) {
	// Delete existing refresh token for this user (single refresh token per user)
	if existingToken, err := m.repo.GetByUserID(userID); err == nil && existingToken != nil {
		if err := m.repo.Delete(existingToken.Token); err != nil {
			return nil, fmt.Errorf("failed to delete existing refresh token: %w", err)
		}
	}

	tokenBytes := make([]byte, m.config.GetRefreshTokenLength()) // Configured length (default: 32 bytes = 256 bits)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	tokenStr := hex.EncodeToString(tokenBytes)
	if err := m.repo.Upsert(&StoredRefreshToken{
		Token:    tokenStr,
		UserID:   userID,
		ClientID: clientID,
		TenantID: tenantID,
		Scope:    scope,
		Iat:      NowTimeFunc(),
	}); err != nil {
		return nil, fmt.Errorf("failed to store refresh token: %w", err)
	}

	return &tokenStr, nil
}

// Get retrieves a refresh token from storage
func (m *Manager) Get(token string) (*StoredRefreshToken, error) {
	return m.repo.Get(token)
}

// Delete removes a refresh token from storage
func (m *Manager) Delete(token string) error {
	return m.repo.Delete(token)
}

// IsExpired checks if a refresh token has expired for the given tenant
func (m *Manager) IsExpired(rt *StoredRefreshToken, tenantExpiry time.Duration) bool {
	if tenantExpiry == 0 {
		tenantExpiry = m.config.GetDefaultRefreshTokenExpiry()
	}
	return NowTimeFunc().Sub(rt.Iat) > tenantExpiry
}

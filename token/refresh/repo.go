package refresh

import (
	"time"
)

// StoredRefreshToken represents the server-side storage of refresh token metadata.
// The client only receives the Token field (a random string). All other fields are
// server-side metadata used for validation and token refresh operations.
type StoredRefreshToken struct {
	Token    string    // The actual random token string (sent to client)
	UserID   string    // Server-side metadata
	ClientID string    // Server-side metadata
	TenantID string    // Server-side metadata (tenant context for expiry)
	Scope    string    // Server-side metadata (original scope for token refresh)
	Iat      time.Time // Server-side metadata (issued at time)
}

// Repo manages server-side storage of refresh token metadata.
// Refresh tokens sent to clients are opaque random strings; this repo stores
// the associated metadata (user, client, tenant, scope, etc.) keyed by the token string.
type Repo interface {
	Upsert(refreshToken *StoredRefreshToken) error
	Delete(token string) error
	Get(token string) (*StoredRefreshToken, error)
	GetByUserID(userID string) (*StoredRefreshToken, error)
	List(offset, limit int) ([]*StoredRefreshToken, error)
}

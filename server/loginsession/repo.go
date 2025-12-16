package loginsession

import "time"

type Session struct {
	// Core identity
	TenantID string
	ClientID string
	UserID   string
	Email    string
	Name     string

	// Tokens (refresh is essential, access is convenience)
	RefreshToken string
	AccessToken  string

	// Authorization
	Scopes []string

	// Session management
	ExpiresAt time.Time
	CreatedAt time.Time
}

type Repo interface {
	Upsert(tenantID, sessionID string, session Session) error
	Get(tenantID, sessionID string) (Session, error)
	Delete(tenantID, sessionID string) error
}

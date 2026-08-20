package adminsession

import "time"

type Session struct {
	TenantID               string
	UserID                 string
	Email                  string
	PasswordChangeRequired bool
	ExpiresAt              time.Time
	CreatedAt              time.Time
}

type Repo interface {
	Upsert(sessionID string, session Session) error
	Get(sessionID string) (Session, error)
	Delete(sessionID string) error
	Close()
}

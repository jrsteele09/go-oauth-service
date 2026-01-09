package authflowsession

import "time"

// Repo defines the interface for session storage operations.
// Sessions are temporary OAuth2 flow state and should be cleaned up regularly.
type Repo interface {
	// Upsert creates or updates a session
	Upsert(sessionID string, sessionData *AuthData) error

	// Delete removes a session by ID
	Delete(sessionID string) error

	// Get retrieves a session by ID
	Get(sessionID string) (*AuthData, error)

	// UpdateUser sets the user email on a session after successful login
	UpdateUser(sessionID, email string) error

	// AssignCodeToSessionID sets the authorization code on a session
	AssignCodeToSessionID(sessionID, code string, ttl time.Duration) error

	// GetSessionFromAuthCode retrieves a session by its authorization code
	GetSessionFromAuthCode(code string) (*AuthData, error)

	// Close releases any resources held by the repo
	Close()
}

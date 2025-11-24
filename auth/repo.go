package auth

type SessionRepo interface {
	Upsert(sessionID string, sessionData *SessionData) error
	Delete(sessionID string) error
	Get(sessionID string) (*SessionData, error)
	UpdateUser(sessionID, email string) error
	AssignCodeToSessionID(sessionID, code string) error
	GetSessionFromAuthCode(code string) (*SessionData, error)
}

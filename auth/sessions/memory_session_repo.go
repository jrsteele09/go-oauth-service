package sessions

import (
	"errors"
	"sync"
	"time"
)

var _ Repo = (*InMemorySessionRepo)(nil)

type InMemorySessionRepo struct {
	sessions map[string]*SessionData
	codes    map[string]string // Map authorization codes to sessionIDs
	lock     sync.RWMutex
}

func NewInMemorySessionRepo() Repo {
	return &InMemorySessionRepo{
		sessions: make(map[string]*SessionData),
		codes:    make(map[string]string),
	}
}

func (sr *InMemorySessionRepo) Upsert(sessionID string, sessionData *SessionData) error {
	sr.lock.Lock()
	defer sr.lock.Unlock()

	sessionData.ID = sessionID
	sr.sessions[sessionID] = sessionData
	return nil
}

func (sr *InMemorySessionRepo) Delete(sessionID string) error {
	sr.lock.Lock()
	defer sr.lock.Unlock()

	session, ok := sr.sessions[sessionID]
	if !ok {
		return errors.New("not found")
	}

	// Clean up authorization code mapping if exists
	if session.AuthCode != "" {
		delete(sr.codes, session.AuthCode)
	}

	delete(sr.sessions, sessionID)
	return nil
}

func (sr *InMemorySessionRepo) Get(sessionID string) (*SessionData, error) {
	sr.lock.RLock()
	defer sr.lock.RUnlock()

	session, ok := sr.sessions[sessionID]
	if !ok {
		return nil, errors.New("not found")
	}
	return session, nil
}

func (sr *InMemorySessionRepo) UpdateUser(sessionID, email string) error {
	sr.lock.Lock()
	defer sr.lock.Unlock()

	session, ok := sr.sessions[sessionID]
	if !ok {
		return errors.New("not found")
	}

	session.UserEmail = email
	return nil
}

func (sr *InMemorySessionRepo) AssignCodeToSessionID(sessionID, code string) error {
	sr.lock.Lock()
	defer sr.lock.Unlock()

	session, ok := sr.sessions[sessionID]
	if !ok {
		return errors.New("not found")
	}

	session.AuthCode = code
	sr.codes[code] = sessionID

	return nil
}

func (sr *InMemorySessionRepo) GetSessionFromAuthCode(code string) (*SessionData, error) {
	sr.lock.RLock()
	defer sr.lock.RUnlock()

	sessionID, ok := sr.codes[code]
	if !ok {
		return nil, errors.New("not found")
	}

	session, ok := sr.sessions[sessionID]
	if !ok {
		return nil, errors.New("not found")
	}

	return session, nil
}

func (sr *InMemorySessionRepo) DeleteExpiredSessions(expiryTime time.Time) error {
	sr.lock.Lock()
	defer sr.lock.Unlock()

	for sessionID, session := range sr.sessions {
		if session.Timestamp.Before(expiryTime) {
			// Clean up authorization code mapping if exists
			if session.AuthCode != "" {
				delete(sr.codes, session.AuthCode)
			}
			delete(sr.sessions, sessionID)
		}
	}

	return nil
}

func (sr *InMemorySessionRepo) SetTokens(sessionID, accessToken, refreshToken, idToken string, tokenExpiry time.Time) error {
	sr.lock.Lock()
	defer sr.lock.Unlock()

	session, ok := sr.sessions[sessionID]
	if !ok {
		return errors.New("not found")
	}

	session.AccessToken = accessToken
	session.RefreshToken = refreshToken
	session.IDToken = idToken
	session.TokenExpiry = tokenExpiry

	return nil
}

package fakesessionrepo

import (
	"errors"
	"sync"
	"time"

	"github.com/jrsteele09/go-auth-server/auth/sessions"
)

var _ sessions.Repo = (*FakeSessionRepo)(nil)

type FakeSessionRepo struct {
	sessions map[string]*sessions.SessionData
	codes    map[string]string // Map authorization codes to sessionIDs
	lock     sync.RWMutex
}

func NewFakeSessionRepo() sessions.Repo {
	return &FakeSessionRepo{
		sessions: make(map[string]*sessions.SessionData),
		codes:    make(map[string]string),
	}
}

func (sr *FakeSessionRepo) Upsert(sessionID string, sessionData *sessions.SessionData) error {
	sr.lock.Lock()
	defer sr.lock.Unlock()

	sessionData.ID = sessionID
	sr.sessions[sessionID] = sessionData
	return nil
}

func (sr *FakeSessionRepo) Delete(sessionID string) error {
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

func (sr *FakeSessionRepo) Get(sessionID string) (*sessions.SessionData, error) {
	sr.lock.RLock()
	defer sr.lock.RUnlock()

	session, ok := sr.sessions[sessionID]
	if !ok {
		return nil, errors.New("not found")
	}
	return session, nil
}

func (sr *FakeSessionRepo) UpdateUser(sessionID, email string) error {
	sr.lock.Lock()
	defer sr.lock.Unlock()

	session, ok := sr.sessions[sessionID]
	if !ok {
		return errors.New("not found")
	}

	session.UserEmail = email
	return nil
}

func (sr *FakeSessionRepo) AssignCodeToSessionID(sessionID, code string) error {
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

func (sr *FakeSessionRepo) GetSessionFromAuthCode(code string) (*sessions.SessionData, error) {
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

func (sr *FakeSessionRepo) DeleteExpiredSessions(expiryTime time.Time) error {
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

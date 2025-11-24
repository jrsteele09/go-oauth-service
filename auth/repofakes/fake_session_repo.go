package fakesessionrepo

import (
	"sync"

	"github.com/jrsteele09/go-auth-server/auth"
	"github.com/pkg/errors"
)

var _ auth.SessionRepo = (*FakeSessionRepo)(nil)

type FakeSessionRepo struct {
	sessions map[string]*auth.SessionData
	codes    map[string]string // Map codes to sessionIDs
	lock     sync.RWMutex
}

func NewFakeSessionRepo() auth.SessionRepo {
	return &FakeSessionRepo{
		sessions: make(map[string]*auth.SessionData),
		codes:    make(map[string]string),
	}
}

func (sr *FakeSessionRepo) Upsert(sessionID string, sessionData *auth.SessionData) error {
	sr.lock.Lock()
	defer sr.lock.Unlock()
	sessionData.SessionID = sessionID
	sr.sessions[sessionID] = sessionData
	return nil
}

func (sr *FakeSessionRepo) Delete(sessionID string) error {
	sr.lock.Lock()
	defer sr.lock.Unlock()

	if _, ok := sr.sessions[sessionID]; !ok {
		return errors.New("not found")
	}
	code := sr.sessions[sessionID].AuthCode
	delete(sr.sessions, sessionID)
	if code != "" {
		delete(sr.codes, code)
	}
	return nil
}

func (sr *FakeSessionRepo) Get(sessionID string) (*auth.SessionData, error) {
	sr.lock.RLock()
	defer sr.lock.RUnlock()

	if _, ok := sr.sessions[sessionID]; !ok {
		return nil, errors.New("not found")
	}
	return sr.sessions[sessionID], nil
}

func (sr *FakeSessionRepo) UpdateUser(sessionID string, email string) error {
	sr.lock.Lock()
	defer sr.lock.Unlock()

	if _, ok := sr.sessions[sessionID]; !ok {
		return errors.New("not found")
	}
	sr.sessions[sessionID].UserEmail = email
	return nil
}

func (sr *FakeSessionRepo) GetSessionFromAuthCode(code string) (*auth.SessionData, error) {
	sr.lock.RLock()
	defer sr.lock.RUnlock()

	if _, ok := sr.codes[code]; !ok {
		return nil, errors.New("not found")
	}
	sessionId := sr.codes[code]
	return sr.sessions[sessionId], nil
}

func (sr *FakeSessionRepo) AssignCodeToSessionID(sessionID, code string) error {
	sessionData, err := sr.Get(sessionID)
	if err != nil {
		return errors.Wrap(err, "AssignCodeToSessionID sr.Get")
	}
	sessionData.AuthCode = code

	if err := sr.Upsert(sessionID, sessionData); err != nil {
		return errors.Wrap(err, "AssignCodeToSessionID sr.Upsert")
	}

	sr.codes[code] = sessionID

	return nil
}

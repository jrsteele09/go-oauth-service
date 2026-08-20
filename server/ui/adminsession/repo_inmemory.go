package adminsession

import (
	"fmt"
	"sync"
	"time"
)

var _ Repo = (*InMemoryRepo)(nil)

type InMemoryRepo struct {
	mu       sync.RWMutex
	sessions map[string]Session
}

func NewInMemoryRepo() *InMemoryRepo {
	return &InMemoryRepo{
		sessions: make(map[string]Session),
	}
}

func (r *InMemoryRepo) Upsert(sessionID string, session Session) error {
	if sessionID == "" {
		return fmt.Errorf("adminsession.Upsert: sessionID is required")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.sessions[sessionID] = session
	return nil
}

func (r *InMemoryRepo) Get(sessionID string) (Session, error) {
	if sessionID == "" {
		return Session{}, fmt.Errorf("adminsession.Get: sessionID is required")
	}

	r.mu.RLock()
	session, ok := r.sessions[sessionID]
	r.mu.RUnlock()
	if !ok {
		return Session{}, fmt.Errorf("adminsession.Get: session not found")
	}

	if !session.ExpiresAt.IsZero() && time.Now().After(session.ExpiresAt) {
		_ = r.Delete(sessionID)
		return Session{}, fmt.Errorf("adminsession.Get: session expired")
	}

	return session, nil
}

func (r *InMemoryRepo) Delete(sessionID string) error {
	if sessionID == "" {
		return nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.sessions, sessionID)
	return nil
}

func (r *InMemoryRepo) Close() {}

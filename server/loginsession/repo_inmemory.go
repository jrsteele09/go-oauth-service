package loginsession

import (
	"fmt"
	"sync"
)

// InMemoryLoginSessionRepo is an in-memory implementation of LoginSessionRepo
type InMemoryLoginSessionRepo struct {
	mu       sync.RWMutex
	sessions map[string]map[string]Session // tenantID -> sessionID -> LoginSession
}

// NewInMemoryLoginSessionRepo creates a new in-memory login session repository
func NewInMemoryLoginSessionRepo() *InMemoryLoginSessionRepo {
	return &InMemoryLoginSessionRepo{
		sessions: make(map[string]map[string]Session),
	}
}

// Upsert creates or updates a login session
func (r *InMemoryLoginSessionRepo) Upsert(tenantID, sessionID string, session Session) error {
	if tenantID == "" {
		return fmt.Errorf("tenantID is required")
	}
	if sessionID == "" {
		return fmt.Errorf("sessionID is required")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Initialize tenant map if it doesn't exist
	if _, ok := r.sessions[tenantID]; !ok {
		r.sessions[tenantID] = make(map[string]Session)
	}

	// Create a copy of the session to avoid external modifications
	r.sessions[tenantID][sessionID] = session
	return nil
}

// Get retrieves a login session by tenant and session ID
func (r *InMemoryLoginSessionRepo) Get(tenantID, sessionID string) (Session, error) {
	if tenantID == "" {
		return Session{}, fmt.Errorf("tenantID is required")
	}
	if sessionID == "" {
		return Session{}, fmt.Errorf("sessionID is required")
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	tenantSessions, ok := r.sessions[tenantID]
	if !ok {
		return Session{}, fmt.Errorf("session not found")
	}

	session, ok := tenantSessions[sessionID]
	if !ok {
		return Session{}, fmt.Errorf("session not found")
	}

	return session, nil
}

// Delete removes a login session
func (r *InMemoryLoginSessionRepo) Delete(tenantID, sessionID string) error {
	if tenantID == "" {
		return fmt.Errorf("tenantID is required")
	}
	if sessionID == "" {
		return fmt.Errorf("sessionID is required")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	tenantSessions, ok := r.sessions[tenantID]
	if !ok {
		return nil // Already doesn't exist, no error
	}

	delete(tenantSessions, sessionID)

	// Clean up empty tenant map
	if len(tenantSessions) == 0 {
		delete(r.sessions, tenantID)
	}

	return nil
}

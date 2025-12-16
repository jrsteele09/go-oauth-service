package authflowrepo

import (
	"errors"
	"sync"
)

// InMemoryRepo is a thread-safe in-memory implementation of the Repo interface
type InMemoryRepo struct {
	mu     sync.RWMutex
	states map[string]*AuthFlowState
}

// NewInMemoryRepo creates a new in-memory auth flow state repository
func NewInMemoryRepo() *InMemoryRepo {
	return &InMemoryRepo{
		states: make(map[string]*AuthFlowState),
	}
}

// Upsert stores or updates an auth flow state
func (r *InMemoryRepo) Upsert(state string, authState *AuthFlowState) error {
	if state == "" {
		return errors.New("state cannot be empty")
	}
	if authState == nil {
		return errors.New("authState cannot be nil")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Create a copy to prevent external modifications
	r.states[state] = &AuthFlowState{
		TenantID:     authState.TenantID,
		CodeVerifier: authState.CodeVerifier,
		Nonce:        authState.Nonce,
		ReturnURL:    authState.ReturnURL,
		CreatedAt:    authState.CreatedAt,
	}

	return nil
}

// Get retrieves an auth flow state by state parameter
func (r *InMemoryRepo) Get(state string) (*AuthFlowState, error) {
	if state == "" {
		return nil, errors.New("state cannot be empty")
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	authState, exists := r.states[state]
	if !exists {
		return nil, errors.New("state not found")
	}

	// Return a copy to prevent external modifications
	return &AuthFlowState{
		TenantID:     authState.TenantID,
		Nonce:        authState.Nonce,
		CodeVerifier: authState.CodeVerifier,
		ReturnURL:    authState.ReturnURL,
		CreatedAt:    authState.CreatedAt,
	}, nil
}

// Delete removes an auth flow state
func (r *InMemoryRepo) Delete(state string) error {
	if state == "" {
		return errors.New("state cannot be empty")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	delete(r.states, state)
	return nil
}

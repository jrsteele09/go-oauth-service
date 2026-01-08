package loginsession

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"sync"
	"time"

	"github.com/jrsteele09/go-kvstore/kvstore"
	"github.com/jrsteele09/go-kvstore/persistence"
)

var _ Repo = (*LoginSessionRepoStore)(nil)

const (
	sessionsSubfolder = "loginsessions"
	evictionInterval  = time.Minute     // Check for expired sessions every minute
	unloadAfter       = 5 * time.Minute // Unload data to disk if not accessed for 5 minutes
	bufferSize        = 10              // Size of the command buffer - how many commands can be queued
)

type LoginSessionRepoStore struct {
	basefolder string
	stores     map[string]*kvstore.Store // tenantID -> kvstore
	mu         sync.RWMutex
}

func NewRepoStore(basefolder string) (Repo, error) {
	return &LoginSessionRepoStore{
		basefolder: basefolder,
		stores:     make(map[string]*kvstore.Store),
	}, nil
}

// getOrCreateStore gets or creates a kvstore for a specific tenant
func (r *LoginSessionRepoStore) getOrCreateStore(tenantID string) (*kvstore.Store, error) {
	r.mu.RLock()
	store, ok := r.stores[tenantID]
	r.mu.RUnlock()

	if ok {
		return store, nil
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check after acquiring write lock - another goroutine might have created it
	if store, ok := r.stores[tenantID]; ok {
		return store, nil
	}

	// Create tenant-specific storage path
	storePath := path.Clean(path.Join(r.basefolder, sessionsSubfolder, tenantID))
	if err := os.MkdirAll(storePath, 0755); err != nil {
		return nil, fmt.Errorf("loginsession.getOrCreateStore: MkdirAll: %w", err)
	}

	fsPersistence, err := persistence.New(storePath)
	if err != nil {
		return nil, fmt.Errorf("loginsession.getOrCreateStore: %w", err)
	}

	bufferedPersistence, err := persistence.NewBuffer(fsPersistence, bufferSize)
	if err != nil {
		return nil, fmt.Errorf("loginsession.getOrCreateStore: %w", err)
	}

	kv, err := kvstore.New(kvstore.WithUnloadFrequencyOption(evictionInterval, unloadAfter), kvstore.WithPersistenceOption(bufferedPersistence))
	if err != nil {
		return nil, fmt.Errorf("loginsession.getOrCreateStore: %w", err)
	}

	r.stores[tenantID] = kv
	return kv, nil
}

func (r *LoginSessionRepoStore) Upsert(tenantID, sessionID string, session Session) error {
	if tenantID == "" {
		return fmt.Errorf("loginsession.Upsert: tenantID is required")
	}
	if sessionID == "" {
		return fmt.Errorf("loginsession.Upsert: sessionID is required")
	}

	store, err := r.getOrCreateStore(tenantID)
	if err != nil {
		return fmt.Errorf("loginsession.Upsert: %w", err)
	}

	data, err := json.Marshal(session)
	if err != nil {
		return fmt.Errorf("loginsession.Upsert: failed to marshal session data: %w", err)
	}

	if err := store.Set(sessionID, data); err != nil {
		return fmt.Errorf("loginsession.Upsert: failed to set session: %w", err)
	}

	// Calculate TTL based on session's ExpiresAt
	ttl := time.Until(session.ExpiresAt)
	if ttl > 0 {
		if err := store.SetTTL(sessionID, int64(ttl.Seconds())); err != nil {
			return fmt.Errorf("loginsession.Upsert: failed to set TTL: %w", err)
		}
	}

	return nil
}

func (r *LoginSessionRepoStore) Get(tenantID, sessionID string) (Session, error) {
	if tenantID == "" {
		return Session{}, fmt.Errorf("loginsession.Get: tenantID is required")
	}
	if sessionID == "" {
		return Session{}, fmt.Errorf("loginsession.Get: sessionID is required")
	}

	store, err := r.getOrCreateStore(tenantID)
	if err != nil {
		return Session{}, fmt.Errorf("loginsession.Get: %w", err)
	}

	data, err := store.Get(sessionID)
	if err != nil {
		return Session{}, errors.New("session not found")
	}

	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return Session{}, fmt.Errorf("loginsession.Get: failed to unmarshal session data: %w", err)
	}

	return session, nil
}

func (r *LoginSessionRepoStore) Delete(tenantID, sessionID string) error {
	if tenantID == "" {
		return fmt.Errorf("loginsession.Delete: tenantID is required")
	}
	if sessionID == "" {
		return fmt.Errorf("loginsession.Delete: sessionID is required")
	}

	store, err := r.getOrCreateStore(tenantID)
	if err != nil {
		return fmt.Errorf("loginsession.Delete: %w", err)
	}

	if err := store.Delete(sessionID); err != nil {
		// Ignore error if key doesn't exist
		return nil
	}

	return nil
}

func (r *LoginSessionRepoStore) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, store := range r.stores {
		store.Close()
	}
}

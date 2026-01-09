package callbackstate

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/jrsteele09/go-kvstore/kvstore"
	"github.com/jrsteele09/go-kvstore/persistence"
)

var _ Repo = (*AuthFlowRepoStore)(nil)

const (
	authSubfolder    = "authstates"
	evictionInterval = 5 * time.Minute // Check for expired items every 5 minutes
	unloadAfter      = 5 * time.Minute // Unload data to disk if not accessed for 5 minutes
	bufferSize       = 10              // Size of the command buffer
)

type AuthFlowRepoStore struct {
	store *kvstore.Store
}

func NewRepoStore(basefolder string) (Repo, error) {
	storePath := path.Clean(path.Join(basefolder, authSubfolder))
	if err := os.MkdirAll(storePath, 0755); err != nil {
		return nil, fmt.Errorf("authflowrepo.NewRepoStore: MkdirAll: %w", err)
	}

	fsPersistence, err := persistence.New(storePath)
	if err != nil {
		return nil, fmt.Errorf("authflowrepo.NewRepoStore: %w", err)
	}

	bufferedPersistence, err := persistence.NewBuffer(fsPersistence, bufferSize)
	if err != nil {
		return nil, fmt.Errorf("authflowrepo.NewRepoStore: %w", err)
	}

	kv, err := kvstore.New(kvstore.WithUnloadFrequencyOption(evictionInterval, unloadAfter), kvstore.WithPersistenceOption(bufferedPersistence))
	if err != nil {
		return nil, fmt.Errorf("authflowrepo.NewRepoStore: %w", err)
	}

	return &AuthFlowRepoStore{
		store: kv,
	}, nil
}

func (r *AuthFlowRepoStore) Upsert(state string, authState *AuthFlowState) error {
	if state == "" {
		return errors.New("authflowrepo.Upsert: state cannot be empty")
	}
	if authState == nil {
		return errors.New("authflowrepo.Upsert: authState cannot be nil")
	}

	data, err := json.Marshal(authState)
	if err != nil {
		return fmt.Errorf("authflowrepo.Upsert: failed to marshal auth state: %w", err)
	}

	if err := r.store.Set(state, data); err != nil {
		return fmt.Errorf("authflowrepo.Upsert: failed to set auth state: %w", err)
	}

	return nil
}

func (r *AuthFlowRepoStore) Get(state string) (*AuthFlowState, error) {
	if state == "" {
		return nil, errors.New("authflowrepo.Get: state cannot be empty")
	}

	data, err := r.store.Get(state)
	if err != nil {
		return nil, errors.New("state not found")
	}

	var authState AuthFlowState
	if err := json.Unmarshal(data, &authState); err != nil {
		return nil, fmt.Errorf("authflowrepo.Get: failed to unmarshal auth state: %w", err)
	}

	return &authState, nil
}

func (r *AuthFlowRepoStore) Delete(state string) error {
	if state == "" {
		return errors.New("authflowrepo.Delete: state cannot be empty")
	}

	if err := r.store.Delete(state); err != nil {
		// Ignore error if key doesn't exist
		return nil
	}

	return nil
}

func (r *AuthFlowRepoStore) Close() {
	r.store.Close()
}

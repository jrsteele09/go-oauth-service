package refresh

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"sync"
	"time"

	"github.com/jrsteele09/go-kvstore/kvstore"
	"github.com/jrsteele09/go-kvstore/persistence"
)

var _ Repo = (*RefreshTokenRepoStore)(nil)

const (
	refreshSubfolder = "tokens"
	evictionInterval = 5 * time.Minute // Check for expired items every 5 minutes
	unloadAfter      = 5 * time.Minute // Unload data to disk if not accessed for 5 minutes
	bufferSize       = 10              // Size of the command buffer
)

type RefreshTokenRepoStore struct {
	basefolder string
	stores     map[string]*kvstore.Store // tenantID -> kvstore
	mu         sync.RWMutex
}

func NewRepoStore(basefolder string) (Repo, error) {
	repo := &RefreshTokenRepoStore{
		basefolder: basefolder,
		stores:     make(map[string]*kvstore.Store),
	}

	// Scan existing tenant folders and initialize stores
	if err := repo.initializeExistingStores(); err != nil {
		return nil, fmt.Errorf("refresh.NewRepoStore: %w", err)
	}

	return repo, nil
}

// initializeExistingStores scans the tokens folder and creates stores for existing tenants
func (r *RefreshTokenRepoStore) initializeExistingStores() error {
	tokensPath := path.Clean(path.Join(r.basefolder, refreshSubfolder))

	// Create directory if it doesn't exist
	if err := os.MkdirAll(tokensPath, 0755); err != nil {
		return fmt.Errorf("MkdirAll: %w", err)
	}

	// Read all subdirectories (each is a tenant)
	entries, err := os.ReadDir(tokensPath)
	if err != nil {
		return fmt.Errorf("ReadDir: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		tenantID := entry.Name()
		// Check if tokens subfolder exists
		tenantTokensPath := path.Join(tokensPath, tenantID)
		if _, err := os.Stat(tenantTokensPath); err != nil {
			continue
		}
		if _, err := r.getOrCreateStore(tenantID, true); err != nil {
			return fmt.Errorf("failed to initialize refresh token store for tenant %s: %w", tenantID, err)
		}

	}

	return nil
}

// getOrCreateStore gets or creates a kvstore for a specific tenant
func (r *RefreshTokenRepoStore) getOrCreateStore(tenantID string, createIfMissing bool) (*kvstore.Store, error) {
	r.mu.RLock()
	store, ok := r.stores[tenantID]
	r.mu.RUnlock()

	if ok {
		return store, nil
	}

	if !createIfMissing {
		return nil, errors.New("store not found")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check after acquiring write lock
	if store, ok := r.stores[tenantID]; ok {
		return store, nil
	}

	// Create tenant-specific storage path
	storePath := path.Clean(path.Join(r.basefolder, refreshSubfolder, tenantID))
	if err := os.MkdirAll(storePath, 0755); err != nil {
		return nil, fmt.Errorf("refresh.getOrCreateStore: MkdirAll: %w", err)
	}

	fsPersistence, err := persistence.New(storePath)
	if err != nil {
		return nil, fmt.Errorf("refresh.getOrCreateStore: %w", err)
	}

	bufferedPersistence, err := persistence.NewBuffer(fsPersistence, bufferSize)
	if err != nil {
		return nil, fmt.Errorf("refresh.getOrCreateStore: %w", err)
	}

	kv, err := kvstore.New(kvstore.WithUnloadFrequencyOption(evictionInterval, unloadAfter), kvstore.WithPersistenceOption(bufferedPersistence))
	if err != nil {
		return nil, fmt.Errorf("refresh.getOrCreateStore: %w", err)
	}

	r.stores[tenantID] = kv
	return kv, nil
}

func (r *RefreshTokenRepoStore) Upsert(tenantID string, refreshToken StoredRefreshToken) error {
	if tenantID == "" {
		return fmt.Errorf("refresh.Upsert: tenantID is required")
	}
	if refreshToken.Token == "" {
		return fmt.Errorf("refresh.Upsert: token is required")
	}

	store, err := r.getOrCreateStore(tenantID, true)
	if err != nil {
		return fmt.Errorf("refresh.Upsert: %w", err)
	}

	data, err := json.Marshal(refreshToken)
	if err != nil {
		return fmt.Errorf("refresh.Upsert: failed to marshal refresh token: %w", err)
	}

	if err := store.Set(refreshToken.Token, data); err != nil {
		return fmt.Errorf("refresh.Upsert: failed to set refresh token: %w", err)
	}

	return nil
}

// SetTTL sets the TTL on a refresh token based on tenant config
func (r *RefreshTokenRepoStore) SetTTL(tenantID, token string, ttl time.Duration) error {
	if tenantID == "" {
		return fmt.Errorf("refresh.SetTTL: tenantID is required")
	}
	if token == "" {
		return fmt.Errorf("refresh.SetTTL: token is required")
	}

	store, err := r.getOrCreateStore(tenantID, false)
	if err != nil {
		return fmt.Errorf("refresh.SetTTL: %w", err)
	}

	if ttl > 0 {
		if err := store.SetTTL(token, int64(ttl.Seconds())); err != nil {
			return fmt.Errorf("refresh.SetTTL: failed to set TTL: %w", err)
		}
	}

	return nil
}

func (r *RefreshTokenRepoStore) Get(tenantID, token string) (StoredRefreshToken, error) {
	if tenantID == "" {
		return StoredRefreshToken{}, fmt.Errorf("refresh.Get: tenantID is required")
	}
	if token == "" {
		return StoredRefreshToken{}, fmt.Errorf("refresh.Get: token is required")
	}

	store, err := r.getOrCreateStore(tenantID, false)
	if err != nil {
		return StoredRefreshToken{}, errors.New("not found")
	}

	data, err := store.Get(token)
	if err != nil {
		return StoredRefreshToken{}, errors.New("not found")
	}

	var refreshToken StoredRefreshToken
	if err := json.Unmarshal(data, &refreshToken); err != nil {
		return StoredRefreshToken{}, fmt.Errorf("refresh.Get: failed to unmarshal refresh token: %w", err)
	}

	return refreshToken, nil
}

func (r *RefreshTokenRepoStore) Delete(tenantID, token string) error {
	if tenantID == "" {
		return fmt.Errorf("refresh.Delete: tenantID is required")
	}
	if token == "" {
		return fmt.Errorf("refresh.Delete: token is required")
	}

	store, err := r.getOrCreateStore(tenantID, false)
	if err != nil {
		return errors.New("not found")
	}

	if err := store.Delete(token); err != nil {
		// Ignore error if key doesn't exist
		return nil
	}

	return nil
}

func (r *RefreshTokenRepoStore) GetByUserID(tenantID, userID string) (*StoredRefreshToken, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("refresh.GetByUserID: tenantID is required")
	}
	if userID == "" {
		return nil, fmt.Errorf("refresh.GetByUserID: userID is required")
	}

	store, err := r.getOrCreateStore(tenantID, false)
	if err != nil {
		return nil, errors.New("not found")
	}

	// Iterate through all keys to find matching userID
	keys := store.Keys()
	for _, key := range keys {
		data, err := store.Get(key)
		if err != nil {
			continue
		}

		var refreshToken StoredRefreshToken
		if err := json.Unmarshal(data, &refreshToken); err != nil {
			continue
		}

		if refreshToken.UserID == userID {
			return &refreshToken, nil
		}
	}

	return nil, errors.New("not found")
}

func (r *RefreshTokenRepoStore) List(tenantID string, offset, limit int) ([]StoredRefreshToken, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("refresh.List: tenantID is required")
	}

	store, err := r.getOrCreateStore(tenantID, false)
	if err != nil {
		return []StoredRefreshToken{}, nil
	}

	keys := store.Keys()
	list := make([]StoredRefreshToken, 0, len(keys))

	for _, key := range keys {
		data, err := store.Get(key)
		if err != nil {
			continue
		}

		var refreshToken StoredRefreshToken
		if err := json.Unmarshal(data, &refreshToken); err != nil {
			continue
		}

		list = append(list, refreshToken)
	}

	// Sort by issued at time
	sort.Slice(list, func(i, j int) bool {
		return list[i].Iat.Before(list[j].Iat)
	})

	// Handle pagination
	total := len(list)
	if offset >= total {
		return []StoredRefreshToken{}, nil
	}

	end := offset + limit
	if end > total {
		end = total
	}

	return list[offset:end], nil
}

func (r *RefreshTokenRepoStore) Count(tenantID string) (int, error) {
	if tenantID == "" {
		return 0, fmt.Errorf("refresh.Count: tenantID is required")
	}

	store, err := r.getOrCreateStore(tenantID, false)
	if err != nil {
		return 0, nil
	}

	return len(store.Keys()), nil
}

func (r *RefreshTokenRepoStore) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, store := range r.stores {
		store.Close()
	}
}

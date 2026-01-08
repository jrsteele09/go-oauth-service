package clients

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

var _ Repo = (*ClientRepoStore)(nil)

const (
	clientsSubfolder = "clients"
	evictionInterval = 5 * time.Minute // Check for expired items every 5 minutes
	unloadAfter      = 5 * time.Minute // Unload data to disk if not accessed for 5 minutes
	bufferSize       = 10              // Size of the command buffer
)

type ClientRepoStore struct {
	basefolder string
	stores     map[string]*kvstore.Store // tenantID -> kvstore
	mu         sync.RWMutex
}

func NewRepoStore(basefolder string) (Repo, error) {
	repo := &ClientRepoStore{
		basefolder: basefolder,
		stores:     make(map[string]*kvstore.Store),
	}

	// Scan existing tenant folders and initialize stores
	if err := repo.initialize(); err != nil {
		return nil, fmt.Errorf("clients.NewRepoStore: %w", err)
	}

	return repo, nil
}

// initialize scans the tenants folder and creates clients stores for existing tenants
func (r *ClientRepoStore) initialize() error {
	clientsPath := path.Clean(path.Join(r.basefolder, clientsSubfolder))

	// Create directory if it doesn't exist
	if err := os.MkdirAll(clientsPath, 0755); err != nil {
		return fmt.Errorf("MkdirAll: %w", err)
	}

	// Read all subdirectories (each is a tenant)
	entries, err := os.ReadDir(clientsPath)
	if err != nil {
		return fmt.Errorf("ReadDir: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		tenantID := entry.Name()
		// Check if clients subfolder exists
		tenantClientsPath := path.Join(clientsPath, tenantID)
		if _, err := os.Stat(tenantClientsPath); err != nil {
			continue
		}

		// Creating the client score will preload the clients for it
		if _, err := r.getOrCreateStore(tenantID, true); err != nil {
			return fmt.Errorf("failed to initialize Client Repo store for tenant %s: %w", tenantID, err)
		}
	}

	return nil
}

// getOrCreateStore gets or creates a kvstore for a specific tenant
func (r *ClientRepoStore) getOrCreateStore(tenantID string, createIfMissing bool) (*kvstore.Store, error) {
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
	storePath := path.Clean(path.Join(r.basefolder, clientsSubfolder, tenantID))
	if err := os.MkdirAll(storePath, 0755); err != nil {
		return nil, fmt.Errorf("clients.getOrCreateStore: MkdirAll: %w", err)
	}

	fsPersistence, err := persistence.New(storePath)
	if err != nil {
		return nil, fmt.Errorf("clients.getOrCreateStore: %w", err)
	}

	bufferedPersistence, err := persistence.NewBuffer(fsPersistence, bufferSize)
	if err != nil {
		return nil, fmt.Errorf("clients.getOrCreateStore: %w", err)
	}

	kv, err := kvstore.New(kvstore.WithUnloadFrequencyOption(evictionInterval, unloadAfter), kvstore.WithPersistenceOption(bufferedPersistence))
	if err != nil {
		return nil, fmt.Errorf("clients.getOrCreateStore: %w", err)
	}

	r.stores[tenantID] = kv
	return kv, nil
}

func (r *ClientRepoStore) Upsert(tenantID string, clientData *Client) error {
	if tenantID == "" {
		return fmt.Errorf("clients.Upsert: tenantID is required")
	}
	if clientData == nil {
		return fmt.Errorf("clients.Upsert: clientData is required")
	}
	if clientData.ID == "" {
		return fmt.Errorf("clients.Upsert: client ID is required")
	}

	store, err := r.getOrCreateStore(tenantID, true)
	if err != nil {
		return fmt.Errorf("clients.Upsert: %w", err)
	}

	data, err := json.Marshal(clientData)
	if err != nil {
		return fmt.Errorf("clients.Upsert: failed to marshal client data: %w", err)
	}

	if err := store.Set(clientData.ID, data); err != nil {
		return fmt.Errorf("clients.Upsert: failed to set client: %w", err)
	}

	return nil
}

func (r *ClientRepoStore) Get(tenantID, clientID string) (*Client, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("clients.Get: tenantID is required")
	}
	if clientID == "" {
		return nil, fmt.Errorf("clients.Get: clientID is required")
	}

	store, err := r.getOrCreateStore(tenantID, false)
	if err != nil {
		return nil, errors.New("not found")
	}

	data, err := store.Get(clientID)
	if err != nil {
		return nil, errors.New("not found")
	}

	var client Client
	if err := json.Unmarshal(data, &client); err != nil {
		return nil, fmt.Errorf("clients.Get: failed to unmarshal client data: %w", err)
	}

	return &client, nil
}

func (r *ClientRepoStore) Delete(tenantID, clientID string) error {
	if tenantID == "" {
		return fmt.Errorf("clients.Delete: tenantID is required")
	}
	if clientID == "" {
		return fmt.Errorf("clients.Delete: clientID is required")
	}

	store, err := r.getOrCreateStore(tenantID, false)
	if err != nil {
		return nil // Already doesn't exist
	}

	if err := store.Delete(clientID); err != nil {
		// Ignore error if key doesn't exist
		return nil
	}

	return nil
}

func (r *ClientRepoStore) List(tenantID string, offset, limit int) ([]*Client, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("clients.List: tenantID is required")
	}

	store, err := r.getOrCreateStore(tenantID, false)
	if err != nil {
		return []*Client{}, nil
	}

	keys := store.Keys()
	list := make([]*Client, 0, len(keys))

	for _, key := range keys {
		data, err := store.Get(key)
		if err != nil {
			continue
		}

		var client Client
		if err := json.Unmarshal(data, &client); err != nil {
			continue
		}

		list = append(list, &client)
	}

	// Sort by ID for consistent ordering
	sort.Slice(list, func(i, j int) bool {
		return list[i].ID < list[j].ID
	})

	// Handle pagination
	total := len(list)
	if offset >= total {
		return []*Client{}, nil
	}

	end := offset + limit
	if end > total {
		end = total
	}

	return list[offset:end], nil
}

func (r *ClientRepoStore) Count(tenantID string) (int, error) {
	if tenantID == "" {
		return 0, fmt.Errorf("clients.Count: tenantID is required")
	}

	store, err := r.getOrCreateStore(tenantID, false)
	if err != nil {
		return 0, nil
	}

	return len(store.Keys()), nil
}

func (r *ClientRepoStore) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, store := range r.stores {
		store.Close()
	}
}

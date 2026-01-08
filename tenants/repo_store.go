package tenants

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"time"

	"github.com/jrsteele09/go-kvstore/kvstore"
	"github.com/jrsteele09/go-kvstore/persistence"
)

var _ Repo = (*TenantRepoStore)(nil)

const (
	tenantsSubfolder = "tenants"
	evictionInterval = time.Minute     // Check for expired items every minute
	unloadAfter      = 5 * time.Minute // Unload data to disk if not accessed for 5 minutes
	bufferSize       = 10              // Size of the command buffer
)

type TenantRepoStore struct {
	store *kvstore.Store
}

func NewRepoStore(basefolder string) (Repo, error) {
	storePath := path.Clean(path.Join(basefolder, tenantsSubfolder))
	if err := os.MkdirAll(storePath, 0755); err != nil {
		return nil, fmt.Errorf("tenants.NewRepoStore: MkdirAll: %w", err)
	}

	fsPersistence, err := persistence.New(storePath)
	if err != nil {
		return nil, fmt.Errorf("tenants.NewRepoStore: %w", err)
	}

	bufferedPersistence, err := persistence.NewBuffer(fsPersistence, bufferSize)
	if err != nil {
		return nil, fmt.Errorf("tenants.NewRepoStore: %w", err)
	}

	kv, err := kvstore.New(kvstore.WithUnloadFrequencyOption(evictionInterval, unloadAfter), kvstore.WithPersistenceOption(bufferedPersistence))
	if err != nil {
		return nil, fmt.Errorf("tenants.NewRepoStore: %w", err)
	}

	return &TenantRepoStore{
		store: kv,
	}, nil
}

func (r *TenantRepoStore) Upsert(tenantData *Tenant) error {
	if tenantData == nil {
		return fmt.Errorf("tenants.Upsert: tenantData is required")
	}
	if tenantData.ID == "" {
		return fmt.Errorf("tenants.Upsert: tenant ID is required")
	}

	data, err := json.Marshal(tenantData)
	if err != nil {
		return fmt.Errorf("tenants.Upsert: failed to marshal tenant data: %w", err)
	}

	if err := r.store.Set(tenantData.ID, data); err != nil {
		return fmt.Errorf("tenants.Upsert: failed to set tenant: %w", err)
	}

	return nil
}

func (r *TenantRepoStore) Get(tenantID string) (*Tenant, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("tenants.Get: tenantID is required")
	}

	data, err := r.store.Get(tenantID)
	if err != nil {
		return nil, errors.New("not found")
	}

	var tenant Tenant
	if err := json.Unmarshal(data, &tenant); err != nil {
		return nil, fmt.Errorf("tenants.Get: failed to unmarshal tenant data: %w", err)
	}

	return &tenant, nil
}

func (r *TenantRepoStore) Delete(tenantID string) error {
	if tenantID == "" {
		return fmt.Errorf("tenants.Delete: tenantID is required")
	}

	if err := r.store.Delete(tenantID); err != nil {
		return fmt.Errorf("tenants.Delete: failed to delete tenant: %w", err)
	}

	return nil
}

func (r *TenantRepoStore) List(offset, limit int) (TenantsListResponse, error) {
	keys := r.store.Keys()
	list := make([]*Tenant, 0, len(keys))

	for _, key := range keys {
		data, err := r.store.Get(key)
		if err != nil {
			continue // Skip if can't get data
		}

		var tenant Tenant
		if err := json.Unmarshal(data, &tenant); err != nil {
			continue // Skip if unmarshal fails
		}

		list = append(list, &tenant)
	}

	// Sort by ID for consistent ordering
	sort.Slice(list, func(i, j int) bool {
		return list[i].ID < list[j].ID
	})

	// Handle pagination
	total := len(list)
	if offset >= total {
		return TenantsListResponse{
			Tenants: []*Tenant{},
			Total:   total,
			Offset:  offset,
			Limit:   limit,
		}, nil
	}

	end := offset + limit
	if end > total {
		end = total
	}

	return TenantsListResponse{
		Tenants: list[offset:end],
		Total:   total,
		Offset:  offset,
		Limit:   limit,
	}, nil
}

func (r *TenantRepoStore) Count() (int, error) {
	return len(r.store.Keys()), nil
}

func (r *TenantRepoStore) Close() error {
	r.store.Close()
	return nil
}

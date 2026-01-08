package tenants

import (
	"errors"
	"sort"
	"sync"

	"github.com/google/uuid"
)

var _ Repo = (*InMemoryRepo)(nil)

type InMemoryRepo struct {
	tenants map[string]*Tenant
	lock    sync.RWMutex
}

func NewInMemoryTenantRepo() Repo {
	return &InMemoryRepo{
		tenants: make(map[string]*Tenant),
	}
}

func (tr *InMemoryRepo) Upsert(tenantData *Tenant) error {
	tr.lock.Lock()
	defer tr.lock.Unlock()
	if tenantData.ID == "" {
		tenantData.ID = uuid.New().String()
	}
	tr.tenants[tenantData.ID] = tenantData
	return nil
}

func (tr *InMemoryRepo) Delete(tenantID string) error {
	tr.lock.Lock()
	defer tr.lock.Unlock()
	if _, ok := tr.tenants[tenantID]; ok {
		tr.tenants[tenantID] = nil
	}
	return nil
}

func (tr *InMemoryRepo) Get(tenantID string) (*Tenant, error) {
	tr.lock.RLock()
	defer tr.lock.RUnlock()
	client, ok := tr.tenants[tenantID]
	if !ok {
		return nil, errors.New("not found")
	}
	return client, nil
}

func (tr *InMemoryRepo) List(offset, limit int) (TenantsListResponse, error) {
	tr.lock.RLock()
	defer tr.lock.RUnlock()

	list := make([]*Tenant, 0)
	for _, t := range tr.tenants {
		list = append(list, t)
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].ID < list[j].ID
	})

	if offset > len(list)-1 {
		return TenantsListResponse{}, nil
	}

	maxLimit := func() int {
		if len(list)-1 < offset+limit {
			return len(list)
		}
		return limit
	}()

	return TenantsListResponse{
		Tenants: list[offset : offset+maxLimit],
		Total:   len(list),
		Offset:  offset,
		Limit:   limit,
	}, nil
}

func (tr *InMemoryRepo) Count() (int, error) {
	tr.lock.RLock()
	defer tr.lock.RUnlock()
	return len(tr.tenants), nil
}

func (tr *InMemoryRepo) Close() error {
	return nil
}

package tenantrepofakes

import (
	"errors"
	"sort"
	"sync"

	"github.com/google/uuid"
	"github.com/jrsteele09/go-auth-server/tenants"
)

var _ tenants.Repo = (*FakeTenantRepo)(nil)

type FakeTenantRepo struct {
	tenants map[string]*tenants.Tenant
	lock    sync.RWMutex
}

func NewFakeTenantRepo() tenants.Repo {
	return &FakeTenantRepo{
		tenants: make(map[string]*tenants.Tenant),
	}
}

func (tr *FakeTenantRepo) Upsert(tenantData *tenants.Tenant) error {
	tr.lock.Lock()
	defer tr.lock.Unlock()
	if tenantData.ID == "" {
		tenantData.ID = uuid.New().String()
	}
	tr.tenants[tenantData.ID] = tenantData
	return nil
}

func (tr *FakeTenantRepo) Delete(tenantID string) error {
	tr.lock.Lock()
	defer tr.lock.Unlock()
	if _, ok := tr.tenants[tenantID]; ok {
		tr.tenants[tenantID] = nil
	}
	return nil
}

func (tr *FakeTenantRepo) Get(tenantID string) (*tenants.Tenant, error) {
	tr.lock.RLock()
	defer tr.lock.RUnlock()
	client, ok := tr.tenants[tenantID]
	if !ok {
		return nil, errors.New("not found")
	}
	return client, nil
}

func (tr *FakeTenantRepo) List(offset, limit int) ([]*tenants.Tenant, error) {
	tr.lock.RLock()
	defer tr.lock.RUnlock()

	tenants := make([]*tenants.Tenant, 0)
	for _, t := range tr.tenants {
		tenants = append(tenants, t)
	}

	sort.Slice(tenants, func(i, j int) bool {
		return tenants[i].ID < tenants[j].ID
	})

	if offset > len(tenants)-1 {
		return nil, nil
	}

	maxLimit := func() int {
		if len(tenants)-1 > offset+limit {
			return len(tenants) - 1
		}
		return limit
	}()

	return tenants[offset : offset+maxLimit], nil
}

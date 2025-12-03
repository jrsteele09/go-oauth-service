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

func (tr *FakeTenantRepo) List(offset, limit int) (tenants.TenantsListResponse, error) {
	tr.lock.RLock()
	defer tr.lock.RUnlock()

	list := make([]*tenants.Tenant, 0)
	for _, t := range tr.tenants {
		list = append(list, t)
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].ID < list[j].ID
	})

	if offset > len(list)-1 {
		return tenants.TenantsListResponse{}, nil
	}

	maxLimit := func() int {
		if len(list)-1 > offset+limit {
			return len(list) - 1
		}
		return limit
	}()

	return tenants.TenantsListResponse{
		Tenants: list[offset : offset+maxLimit],
		Total:   len(list),
		Offset:  offset,
		Limit:   limit,
	}, nil
}

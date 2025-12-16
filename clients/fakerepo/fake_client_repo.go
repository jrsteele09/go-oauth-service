package fakeclientrepo

import (
	"errors"
	"sort"
	"sync"

	"github.com/google/uuid"
	"github.com/jrsteele09/go-auth-server/clients"
)

var _ clients.Repo = (*FakeClientRepo)(nil)

type FakeClientRepo struct {
	clients map[string]map[string]*clients.Client // tenantID -> clientID -> Client
	lock    sync.RWMutex
}

func NewFakeClientRepo() clients.Repo {
	return &FakeClientRepo{
		clients: make(map[string]map[string]*clients.Client),
	}
}

func (r *FakeClientRepo) Upsert(tenantID string, clientData *clients.Client) error {
	r.lock.Lock()
	defer r.lock.Unlock()

	if clientData.ID == "" {
		clientData.ID = uuid.New().String()
	}

	// Initialize tenant map if it doesn't exist
	if r.clients[tenantID] == nil {
		r.clients[tenantID] = make(map[string]*clients.Client)
	}

	r.clients[tenantID][clientData.ID] = clientData
	return nil
}

func (r *FakeClientRepo) Delete(tenantID, clientID string) error {
	r.lock.Lock()
	defer r.lock.Unlock()

	if tenantClients, ok := r.clients[tenantID]; ok {
		delete(tenantClients, clientID)

		// Clean up empty tenant map
		if len(tenantClients) == 0 {
			delete(r.clients, tenantID)
		}
	}
	return nil
}

func (r *FakeClientRepo) Get(tenantID, clientID string) (*clients.Client, error) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	tenantClients, ok := r.clients[tenantID]
	if !ok {
		return nil, errors.New("not found")
	}

	client, ok := tenantClients[clientID]
	if !ok {
		return nil, errors.New("not found")
	}
	return client, nil
}

func (r *FakeClientRepo) List(tenantID string, offset, limit int) ([]*clients.Client, error) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	tenantClients, ok := r.clients[tenantID]
	if !ok {
		return []*clients.Client{}, nil
	}

	clientList := make([]*clients.Client, 0)
	for _, v := range tenantClients {
		clientList = append(clientList, v)
	}

	sort.Slice(clientList, func(i, j int) bool {
		return clientList[i].ID < clientList[j].ID
	})

	if offset > len(clientList)-1 {
		return []*clients.Client{}, nil
	}

	maxLimit := func() int {
		if len(clientList)-1 > offset+limit {
			return len(clientList) - 1
		}
		return limit
	}()

	return clientList[offset : offset+maxLimit], nil
}

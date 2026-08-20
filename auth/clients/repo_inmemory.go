package clients

import (
	"errors"
	"sort"
	"sync"

	"github.com/google/uuid"
)

var _ Repo = (*InMemoryClientRepo)(nil)

type InMemoryClientRepo struct {
	clients map[string]map[string]*Client // tenantID -> clientID -> Client
	lock    sync.RWMutex
}

func NewInMemoryClientRepo() Repo {
	return &InMemoryClientRepo{
		clients: make(map[string]map[string]*Client),
	}
}

func (r *InMemoryClientRepo) Upsert(tenantID string, clientData *Client) error {
	r.lock.Lock()
	defer r.lock.Unlock()

	if clientData.ID == "" {
		clientData.ID = uuid.New().String()
	}

	// Initialize tenant map if it doesn't exist
	if r.clients[tenantID] == nil {
		r.clients[tenantID] = make(map[string]*Client)
	}

	r.clients[tenantID][clientData.ID] = clientData
	return nil
}

func (r *InMemoryClientRepo) Delete(tenantID, clientID string) error {
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

func (r *InMemoryClientRepo) Get(tenantID, clientID string) (*Client, error) {
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

func (r *InMemoryClientRepo) List(tenantID string, offset, limit int) ([]*Client, error) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	tenantClients, ok := r.clients[tenantID]
	if !ok {
		return []*Client{}, nil
	}

	clientList := make([]*Client, 0)
	for _, v := range tenantClients {
		clientList = append(clientList, v)
	}

	sort.Slice(clientList, func(i, j int) bool {
		return clientList[i].ID < clientList[j].ID
	})

	if offset > len(clientList)-1 {
		return []*Client{}, nil
	}

	maxLimit := func() int {
		if len(clientList)-1 > offset+limit {
			return len(clientList) - 1
		}
		return limit
	}()

	return clientList[offset : offset+maxLimit], nil
}

func (r *InMemoryClientRepo) Count(tenantID string) (int, error) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	tenantClients, ok := r.clients[tenantID]
	if !ok {
		return 0, nil
	}
	return len(tenantClients), nil
}

func (r *InMemoryClientRepo) Close() {
	// No resources to clean up for in-memory repo
}

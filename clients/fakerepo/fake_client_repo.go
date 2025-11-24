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
	clients map[string]*clients.Client
	lock    sync.RWMutex
}

func NewFakeClientRepo() clients.Repo {
	return &FakeClientRepo{
		clients: make(map[string]*clients.Client),
	}
}

func (r *FakeClientRepo) Upsert(clientData *clients.Client) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	if clientData.ID == "" {
		clientData.ID = uuid.New().String()
	}
	r.clients[clientData.ID] = clientData
	return nil
}

func (r *FakeClientRepo) Delete(clientID string) error {
	r.lock.Lock()
	defer r.lock.Unlock()
	if _, ok := r.clients[clientID]; ok {
		r.clients[clientID] = nil
	}
	return nil
}

func (r *FakeClientRepo) Get(clientID string) (*clients.Client, error) {
	r.lock.RLock()
	defer r.lock.RUnlock()
	client, ok := r.clients[clientID]
	if !ok {
		return nil, errors.New("not found")
	}
	return client, nil
}

func (r *FakeClientRepo) List(offset, limit int) ([]*clients.Client, error) {
	r.lock.RLock()
	defer r.lock.RUnlock()

	clients := make([]*clients.Client, 0)
	for _, v := range r.clients {
		clients = append(clients, v)
	}

	sort.Slice(clients, func(i, j int) bool {
		return clients[i].ID < clients[j].ID
	})

	if offset > len(clients)-1 {
		return nil, nil
	}

	maxLimit := func() int {
		if len(clients)-1 > offset+limit {
			return len(clients) - 1
		}
		return limit
	}()

	return clients[offset : offset+maxLimit], nil
}

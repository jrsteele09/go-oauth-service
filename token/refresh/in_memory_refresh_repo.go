package refresh

import (
	"errors"
	"sort"
	"sync"
)

var _ Repo = (*InMemoryRefreshTokenRepo)(nil)

type InMemoryRefreshTokenRepo struct {
	tokens  map[string]map[string]StoredRefreshToken // tenantID -> token -> StoredRefreshToken
	userIDs map[string]map[string]string             // tenantID -> userID -> token
	lock    sync.RWMutex
}

func NewInMemoryRefreshTokenRepo() Repo {
	return &InMemoryRefreshTokenRepo{
		tokens:  make(map[string]map[string]StoredRefreshToken),
		userIDs: make(map[string]map[string]string),
	}
}

func (tr *InMemoryRefreshTokenRepo) Upsert(tenantID string, refreshToken StoredRefreshToken) error {
	tr.lock.Lock()
	defer tr.lock.Unlock()

	if tr.tokens[tenantID] == nil {
		tr.tokens[tenantID] = make(map[string]StoredRefreshToken)
	}
	if tr.userIDs[tenantID] == nil {
		tr.userIDs[tenantID] = make(map[string]string)
	}

	tr.tokens[tenantID][refreshToken.Token] = refreshToken
	tr.userIDs[tenantID][refreshToken.UserID] = refreshToken.Token
	return nil
}

func (tr *InMemoryRefreshTokenRepo) Delete(tenantID, token string) error {
	tr.lock.Lock()
	defer tr.lock.Unlock()

	if tr.tokens[tenantID] == nil {
		return errors.New("not found")
	}

	rt, ok := tr.tokens[tenantID][token]
	if !ok {
		return errors.New("not found")
	}

	delete(tr.userIDs[tenantID], rt.UserID)
	delete(tr.tokens[tenantID], rt.Token)
	return nil
}

func (tr *InMemoryRefreshTokenRepo) Get(tenantID, token string) (StoredRefreshToken, error) {
	tr.lock.RLock()
	defer tr.lock.RUnlock()

	if tr.tokens[tenantID] == nil {
		return StoredRefreshToken{}, errors.New("not found")
	}

	rt, ok := tr.tokens[tenantID][token]
	if !ok {
		return StoredRefreshToken{}, errors.New("not found")
	}
	return rt, nil
}

func (tr *InMemoryRefreshTokenRepo) GetByUserID(tenantID, userID string) (*StoredRefreshToken, error) {
	tr.lock.RLock()
	defer tr.lock.RUnlock()

	if tr.userIDs[tenantID] == nil {
		return nil, errors.New("not found")
	}

	tokenID, ok := tr.userIDs[tenantID][userID]
	if !ok {
		return nil, errors.New("not found")
	}

	rt := tr.tokens[tenantID][tokenID]
	return &rt, nil
}

func (tr *InMemoryRefreshTokenRepo) List(tenantID string, offset, limit int) ([]StoredRefreshToken, error) {
	tr.lock.RLock()
	defer tr.lock.RUnlock()

	if tr.tokens[tenantID] == nil {
		return []StoredRefreshToken{}, nil
	}

	tokens := make([]StoredRefreshToken, 0)
	for _, v := range tr.tokens[tenantID] {
		tokens = append(tokens, v)
	}

	sort.Slice(tokens, func(i, j int) bool {
		return tokens[i].Iat.Before(tokens[j].Iat)
	})

	if offset > len(tokens)-1 {
		return []StoredRefreshToken{}, nil
	}

	end := offset + limit
	if end > len(tokens) {
		end = len(tokens)
	}

	return tokens[offset:end], nil
}

func (tr *InMemoryRefreshTokenRepo) Count(tenantID string) (int, error) {
	tr.lock.RLock()
	defer tr.lock.RUnlock()

	if tr.tokens[tenantID] == nil {
		return 0, nil
	}

	return len(tr.tokens[tenantID]), nil
}

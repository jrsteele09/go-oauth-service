package refreshrepofake

import (
	"errors"
	"sort"
	"sync"

	"github.com/jrsteele09/go-auth-server/token/refresh"
)

var _ refresh.Repo = (*FakeRefreshTokenRepo)(nil)

type FakeRefreshTokenRepo struct {
	tokens  map[string]*refresh.StoredRefreshToken
	userIDs map[string]string // user ID to token ID
	lock    sync.RWMutex
}

func NewFakeRefreshTokenRepo() refresh.Repo {
	return &FakeRefreshTokenRepo{
		tokens:  make(map[string]*refresh.StoredRefreshToken),
		userIDs: make(map[string]string),
	}
}

func (tr *FakeRefreshTokenRepo) Upsert(refreshToken *refresh.StoredRefreshToken) error {
	tr.lock.Lock()
	defer tr.lock.Unlock()

	tr.tokens[refreshToken.Token] = refreshToken
	tr.userIDs[refreshToken.UserID] = refreshToken.Token
	return nil
}

func (tr *FakeRefreshTokenRepo) Delete(token string) error {
	tr.lock.Lock()
	defer tr.lock.Unlock()

	rt, ok := tr.tokens[token]
	if !ok {
		return errors.New("not found")
	}
	delete(tr.userIDs, rt.UserID)

	if _, ok := tr.tokens[rt.Token]; !ok {
		return nil
	}

	delete(tr.tokens, rt.Token)
	return nil
}

func (tr *FakeRefreshTokenRepo) Get(token string) (*refresh.StoredRefreshToken, error) {
	tr.lock.RLock()
	defer tr.lock.RUnlock()
	if _, ok := tr.tokens[token]; !ok {
		return nil, errors.New("not found")
	}
	return tr.tokens[token], nil
}

func (tr *FakeRefreshTokenRepo) GetByUserID(userID string) (*refresh.StoredRefreshToken, error) {
	tr.lock.RLock()
	defer tr.lock.RUnlock()
	if _, ok := tr.userIDs[userID]; !ok {
		return nil, errors.New("not found")
	}
	return tr.tokens[tr.userIDs[userID]], nil
}

func (tr *FakeRefreshTokenRepo) List(offset, limit int) ([]*refresh.StoredRefreshToken, error) {
	tr.lock.RLock()
	defer tr.lock.RUnlock()

	tokens := make([]*refresh.StoredRefreshToken, 0)
	for _, v := range tr.tokens {
		tokens = append(tokens, v)
	}

	sort.Slice(tokens, func(i, j int) bool {
		return tokens[i].Iat.Before(tokens[j].Iat)
	})

	if offset > len(tokens)-1 {
		return nil, nil
	}

	maxLimit := func() int {
		if len(tokens)-1 > offset+limit {
			return len(tokens) - 1
		}
		return limit
	}()

	return tokens[offset : offset+maxLimit], nil
}

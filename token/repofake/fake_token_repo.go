package tokenfakerepo

import (
	"errors"
	"sort"
	"sync"

	"github.com/jrsteele09/go-auth-server/token"
)

var _ token.RefreshTokenRepo = (*FakeTokenRepo)(nil)

type FakeTokenRepo struct {
	tokens  map[string]*token.RefreshToken
	userIDs map[string]string // user ID to token ID
	lock    sync.RWMutex
}

func NewFakeTokensRepo() token.RefreshTokenRepo {
	return &FakeTokenRepo{
		tokens:  make(map[string]*token.RefreshToken),
		userIDs: make(map[string]string),
	}
}

func (tr *FakeTokenRepo) Upsert(refreshToken *token.RefreshToken) error {
	tr.lock.Lock()
	defer tr.lock.Unlock()

	tr.tokens[refreshToken.Token] = refreshToken
	tr.userIDs[refreshToken.UserID] = refreshToken.Token
	return nil
}

func (tr *FakeTokenRepo) Delete(token string) error {
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

func (tr *FakeTokenRepo) Get(token string) (*token.RefreshToken, error) {
	tr.lock.RLock()
	defer tr.lock.RUnlock()
	if _, ok := tr.tokens[token]; !ok {
		return nil, errors.New("not found")
	}
	return tr.tokens[token], nil

}

func (tr *FakeTokenRepo) GetByUserID(userID string) (*token.RefreshToken, error) {
	tr.lock.RLock()
	defer tr.lock.RUnlock()
	if _, ok := tr.userIDs[userID]; !ok {
		return nil, errors.New("not found")
	}
	return tr.tokens[tr.userIDs[userID]], nil
}

func (tr *FakeTokenRepo) List(offset, limit int) ([]*token.RefreshToken, error) {
	tr.lock.RLock()
	defer tr.lock.RUnlock()

	tokens := make([]*token.RefreshToken, 0)
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

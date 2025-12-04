package fakeuserrepo

import (
	"errors"
	"sort"
	"sync"

	"github.com/google/uuid"
	"github.com/jrsteele09/go-auth-server/users"
)

var _ users.UserRepo = (*FakeUserRepo)(nil)

type FakeUserRepo struct {
	users    map[string]*users.User
	emailIds map[string]string // email to user id
	lock     sync.RWMutex
	// sessions map[string]*auth.SessionData
	// codes    map[string]string // Map codes to sessionIDs
}

func NewFakeUserRepo() users.UserRepo {
	return &FakeUserRepo{
		users:    make(map[string]*users.User),
		emailIds: make(map[string]string),
	}
}

func (ur *FakeUserRepo) Upsert(user *users.User) error {
	ur.lock.Lock()
	defer ur.lock.Unlock()

	if user.ID == "" {
		user.ID = uuid.New().String()
	}
	ur.users[user.ID] = user
	ur.emailIds[user.Email] = user.ID
	return nil
}

func (ur *FakeUserRepo) Delete(email string) error {
	ur.lock.Lock()
	defer ur.lock.Unlock()

	userID, ok := ur.emailIds[email]
	if !ok {
		return errors.New("not found")
	}
	delete(ur.emailIds, email)

	if _, ok := ur.users[userID]; !ok {
		return nil
	}

	delete(ur.users, userID)
	return nil
}

func (ur *FakeUserRepo) GetByEmail(email string) (*users.User, error) {
	ur.lock.RLock()
	defer ur.lock.RUnlock()

	if _, ok := ur.emailIds[email]; !ok {
		return nil, errors.New("not found")
	}
	return ur.users[ur.emailIds[email]], nil
}

func (ur *FakeUserRepo) GetByID(id string) (*users.User, error) {
	ur.lock.RLock()
	defer ur.lock.RUnlock()

	if _, ok := ur.users[id]; !ok {
		return nil, errors.New("not found")
	}
	return ur.users[id], nil
}

func (ur *FakeUserRepo) List(tenantID string, offset, limit int) (users.UsersListResponse, error) {
	ur.lock.RLock()
	defer ur.lock.RUnlock()

	userList := make([]*users.User, 0)
	for _, v := range ur.users {
		// Filter by tenant if specified
		if tenantID != "" && !v.HasTenant(tenantID) {
			continue
		}
		userList = append(userList, v)
	}

	sort.Slice(userList, func(i, j int) bool {
		return userList[i].ID < userList[j].ID
	})

	if offset > len(userList)-1 {
		return users.UsersListResponse{}, nil
	}

	maxLimit := func() int {
		if len(userList)-1 > offset+limit {
			return len(userList) - 1
		}
		return limit
	}()

	return users.UsersListResponse{
		Users:  userList[offset : offset+maxLimit],
		Total:  len(userList),
		Offset: offset,
		Limit:  maxLimit,
	}, nil
}

func (ur *FakeUserRepo) SetBlocked(email string, blocked bool) error {
	user, err := ur.GetByEmail(email)
	if err != nil {
		return err
	}
	user.Blocked = blocked
	return nil
}

func (ur *FakeUserRepo) SetVerified(email string, verified bool) error {
	user, err := ur.GetByEmail(email)
	if err != nil {
		return err
	}
	user.Verified = verified
	return nil
}

func (ur *FakeUserRepo) SetLoggedIn(email string, loggedIn bool) error {
	user, err := ur.GetByEmail(email)
	if err != nil {
		return err
	}
	user.LoggedIn = loggedIn
	return nil
}

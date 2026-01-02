package users

import (
	"errors"
	"sort"
	"sync"

	"github.com/google/uuid"
)

var _ UserRepo = (*InMemoryUserRepo)(nil)

type tenant string
type InMemoryUserRepo struct {
	users    map[tenant]map[string]*User
	emailIds map[tenant]map[string]string // email to user id
	lock     sync.RWMutex
	// sessions map[string]*auth.SessionData
	// codes    map[string]string // Map codes to sessionIDs
}

func NewInMemoryUserRepo() UserRepo {
	return &InMemoryUserRepo{
		users:    make(map[tenant]map[string]*User),
		emailIds: make(map[tenant]map[string]string),
	}
}

func (ur *InMemoryUserRepo) getMapsForTenant(tenantID string) (map[string]*User, map[string]string) {
	if _, ok := ur.users[tenant(tenantID)]; !ok {
		ur.users[tenant(tenantID)] = make(map[string]*User)
		ur.emailIds[tenant(tenantID)] = make(map[string]string)
	}
	return ur.users[tenant(tenantID)], ur.emailIds[tenant(tenantID)]
}

func (ur *InMemoryUserRepo) Upsert(tenantID string, user *User) error {
	ur.lock.Lock()
	defer ur.lock.Unlock()

	if user.ID == "" {
		user.ID = uuid.New().String()
	}
	userMap, emailMap := ur.getMapsForTenant(tenantID)
	userMap[user.ID] = user
	emailMap[user.Email] = user.ID
	return nil
}

func (ur *InMemoryUserRepo) Delete(tenantID, email string) error {
	ur.lock.Lock()
	defer ur.lock.Unlock()

	userMap, emailMap := ur.getMapsForTenant(tenantID)

	userID, ok := emailMap[email]
	if !ok {
		return errors.New("not found")
	}
	delete(emailMap, email)
	if _, ok := userMap[userID]; !ok {
		return nil
	}

	delete(userMap, userID)
	return nil
}

func (ur *InMemoryUserRepo) GetByEmail(tenantID, email string) (*User, error) {
	ur.lock.RLock()
	defer ur.lock.RUnlock()
	userMap, emailMap := ur.getMapsForTenant(tenantID)
	if _, ok := emailMap[email]; !ok {
		return nil, errors.New("not found")
	}
	return userMap[emailMap[email]], nil
}

func (ur *InMemoryUserRepo) GetByID(tenantID, id string) (*User, error) {
	ur.lock.RLock()
	defer ur.lock.RUnlock()

	userMap, _ := ur.getMapsForTenant(tenantID)

	if _, ok := userMap[id]; !ok {
		return nil, errors.New("not found")
	}
	return userMap[id], nil
}

func (ur *InMemoryUserRepo) List(tenantID string, offset, limit int) (UsersListResponse, error) {
	ur.lock.RLock()
	defer ur.lock.RUnlock()

	userList := make([]*User, 0)

	userMap, _ := ur.getMapsForTenant(tenantID)

	for _, v := range userMap {
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
		return UsersListResponse{}, nil
	}

	maxLimit := func() int {
		if len(userList)-1 > offset+limit {
			return len(userList) - 1
		}
		return limit
	}()

	return UsersListResponse{
		Users:  userList[offset : offset+maxLimit],
		Total:  len(userList),
		Offset: offset,
		Limit:  maxLimit,
	}, nil
}

func (ur *InMemoryUserRepo) SetBlocked(tenantID, email string, blocked bool) error {
	user, err := ur.GetByEmail(tenantID, email)
	if err != nil {
		return err
	}
	user.Blocked = blocked
	return nil
}

func (ur *InMemoryUserRepo) SetVerified(tenantID, email string, verified bool) error {
	user, err := ur.GetByEmail(tenantID, email)
	if err != nil {
		return err
	}
	user.Verified = verified
	return nil
}

func (ur *InMemoryUserRepo) SetLoggedIn(tenantID, email string, loggedIn bool) error {
	user, err := ur.GetByEmail(tenantID, email)
	if err != nil {
		return err
	}
	user.LoggedIn = loggedIn
	return nil
}

func (ur *InMemoryUserRepo) Count(tenantID string) (int, error) {
	ur.lock.RLock()
	defer ur.lock.RUnlock()

	userMap, _ := ur.getMapsForTenant(tenantID)
	return len(userMap), nil
}

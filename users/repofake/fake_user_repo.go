package fakeuserrepo

import (
	"errors"
	"sort"
	"sync"

	"github.com/google/uuid"
	"github.com/jrsteele09/go-auth-server/users"
)

var _ users.UserRepo = (*FakeUserRepo)(nil)

type tenant string
type FakeUserRepo struct {
	users    map[tenant]map[string]*users.User
	emailIds map[tenant]map[string]string // email to user id
	lock     sync.RWMutex
	// sessions map[string]*auth.SessionData
	// codes    map[string]string // Map codes to sessionIDs
}

func NewFakeUserRepo() users.UserRepo {
	return &FakeUserRepo{
		users:    make(map[tenant]map[string]*users.User),
		emailIds: make(map[tenant]map[string]string),
	}
}

func (ur *FakeUserRepo) getMapsForTenant(tenantID string) (map[string]*users.User, map[string]string) {
	if _, ok := ur.users[tenant(tenantID)]; !ok {
		ur.users[tenant(tenantID)] = make(map[string]*users.User)
		ur.emailIds[tenant(tenantID)] = make(map[string]string)
	}
	return ur.users[tenant(tenantID)], ur.emailIds[tenant(tenantID)]
}

func (ur *FakeUserRepo) Upsert(tenantID string, user *users.User) error {
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

func (ur *FakeUserRepo) Delete(tenantID, email string) error {
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

func (ur *FakeUserRepo) GetByEmail(tenantID, email string) (*users.User, error) {
	ur.lock.RLock()
	defer ur.lock.RUnlock()
	userMap, emailMap := ur.getMapsForTenant(tenantID)
	if _, ok := emailMap[email]; !ok {
		return nil, errors.New("not found")
	}
	return userMap[emailMap[email]], nil
}

func (ur *FakeUserRepo) GetByID(tenantID, id string) (*users.User, error) {
	ur.lock.RLock()
	defer ur.lock.RUnlock()

	userMap, _ := ur.getMapsForTenant(tenantID)

	if _, ok := userMap[id]; !ok {
		return nil, errors.New("not found")
	}
	return userMap[id], nil
}

func (ur *FakeUserRepo) List(tenantID string, offset, limit int) (users.UsersListResponse, error) {
	ur.lock.RLock()
	defer ur.lock.RUnlock()

	userList := make([]*users.User, 0)

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

func (ur *FakeUserRepo) SetBlocked(tenantID, email string, blocked bool) error {
	user, err := ur.GetByEmail(tenantID, email)
	if err != nil {
		return err
	}
	user.Blocked = blocked
	return nil
}

func (ur *FakeUserRepo) SetVerified(tenantID, email string, verified bool) error {
	user, err := ur.GetByEmail(tenantID, email)
	if err != nil {
		return err
	}
	user.Verified = verified
	return nil
}

func (ur *FakeUserRepo) SetLoggedIn(tenantID, email string, loggedIn bool) error {
	user, err := ur.GetByEmail(tenantID, email)
	if err != nil {
		return err
	}
	user.LoggedIn = loggedIn
	return nil
}

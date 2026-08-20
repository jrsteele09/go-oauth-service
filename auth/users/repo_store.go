package users

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"sort"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jrsteele09/go-kvstore/kvstore"
	"github.com/jrsteele09/go-kvstore/persistence"
)

var _ UserRepo = (*UserRepoStore)(nil)

const (
	usersSubfolder   = "users"
	evictionInterval = 5 * time.Minute
	unloadAfter      = 5 * time.Minute
	bufferSize       = 10
)

type UserRepoStore struct {
	basefolder string
	stores     map[string]*kvstore.Store // tenantID -> kvstore
	mu         sync.RWMutex
}

func NewRepoStore(basefolder string) (UserRepo, error) {
	repo := &UserRepoStore{
		basefolder: basefolder,
		stores:     make(map[string]*kvstore.Store),
	}

	if err := repo.initialize(); err != nil {
		return nil, fmt.Errorf("users.NewRepoStore: %w", err)
	}

	return repo, nil
}

func (r *UserRepoStore) initialize() error {
	tenantsPath := path.Clean(path.Join(r.basefolder, usersSubfolder))

	if err := os.MkdirAll(tenantsPath, 0755); err != nil {
		return fmt.Errorf("MkdirAll: %w", err)
	}

	entries, err := os.ReadDir(tenantsPath)
	if err != nil {
		return fmt.Errorf("ReadDir: %w", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		tenantID := entry.Name()
		tenantUsersPath := path.Join(tenantsPath, tenantID)
		if _, err := os.Stat(tenantUsersPath); err != nil {
			continue
		}
		if _, err := r.getOrCreateStore(tenantID, true); err != nil {
			return fmt.Errorf("failed to initialize User Repo store for tenant %s: %w", tenantID, err)
		}
	}

	return nil
}

func (r *UserRepoStore) getOrCreateStore(tenantID string, createIfMissing bool) (*kvstore.Store, error) {
	r.mu.RLock()
	store, ok := r.stores[tenantID]
	r.mu.RUnlock()

	if ok {
		return store, nil
	}

	if !createIfMissing {
		return nil, errors.New("store not found")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if store, ok := r.stores[tenantID]; ok {
		return store, nil
	}

	storePath := path.Clean(path.Join(r.basefolder, usersSubfolder, tenantID))
	if err := os.MkdirAll(storePath, 0755); err != nil {
		return nil, fmt.Errorf("users.getOrCreateStore: MkdirAll: %w", err)
	}

	fsPersistence, err := persistence.New(storePath)
	if err != nil {
		return nil, fmt.Errorf("users.getOrCreateStore: %w", err)
	}

	bufferedPersistence, err := persistence.NewBuffer(fsPersistence, bufferSize)
	if err != nil {
		return nil, fmt.Errorf("users.getOrCreateStore: %w", err)
	}

	kv, err := kvstore.New(kvstore.WithUnloadFrequencyOption(evictionInterval, unloadAfter), kvstore.WithPersistenceOption(bufferedPersistence))
	if err != nil {
		return nil, fmt.Errorf("users.getOrCreateStore: %w", err)
	}

	r.stores[tenantID] = kv
	return kv, nil
}

func (r *UserRepoStore) Upsert(tenantID string, user *User) error {
	if tenantID == "" {
		return fmt.Errorf("users.Upsert: tenantID is required")
	}
	if user == nil {
		return fmt.Errorf("users.Upsert: user is required")
	}

	r.mu.Lock()
	if user.ID == "" {
		user.ID = uuid.New().String()
	}
	r.mu.Unlock()

	store, err := r.getOrCreateStore(tenantID, true)
	if err != nil {
		return fmt.Errorf("users.Upsert: %w", err)
	}

	data, err := json.Marshal(user)
	if err != nil {
		return fmt.Errorf("users.Upsert: failed to marshal user data: %w", err)
	}

	// Store user data with user/{id} key
	if err := store.Set("user/"+user.ID, data); err != nil {
		return fmt.Errorf("users.Upsert: failed to set user: %w", err)
	}

	// Store email→id mapping with email/{email} key
	if err := store.Set("email/"+user.Email, []byte(user.ID)); err != nil {
		return fmt.Errorf("users.Upsert: failed to set email index: %w", err)
	}

	return nil
}

func (r *UserRepoStore) GetByEmail(tenantID, email string) (*User, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("users.GetByEmail: tenantID is required")
	}
	if email == "" {
		return nil, fmt.Errorf("users.GetByEmail: email is required")
	}

	store, err := r.getOrCreateStore(tenantID, false)
	if err != nil {
		return nil, errors.New("not found")
	}

	// Get userID from email index
	userIDBytes, err := store.Get("email/" + email)
	if err != nil {
		return nil, errors.New("not found")
	}

	userID := string(userIDBytes)

	// Get user data
	data, err := store.Get("user/" + userID)
	if err != nil {
		return nil, errors.New("not found")
	}

	var user User
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, fmt.Errorf("users.GetByEmail: failed to unmarshal user data: %w", err)
	}

	return &user, nil
}

func (r *UserRepoStore) GetByID(tenantID, id string) (*User, error) {
	if tenantID == "" {
		return nil, fmt.Errorf("users.GetByID: tenantID is required")
	}
	if id == "" {
		return nil, fmt.Errorf("users.GetByID: id is required")
	}

	store, err := r.getOrCreateStore(tenantID, false)
	if err != nil {
		return nil, errors.New("not found")
	}

	data, err := store.Get("user/" + id)
	if err != nil {
		return nil, errors.New("not found")
	}

	var user User
	if err := json.Unmarshal(data, &user); err != nil {
		return nil, fmt.Errorf("users.GetByID: failed to unmarshal user data: %w", err)
	}

	return &user, nil
}

func (r *UserRepoStore) Delete(tenantID, email string) error {
	if tenantID == "" {
		return fmt.Errorf("users.Delete: tenantID is required")
	}
	if email == "" {
		return fmt.Errorf("users.Delete: email is required")
	}

	store, err := r.getOrCreateStore(tenantID, false)
	if err != nil {
		return errors.New("not found")
	}

	// Get userID from email index
	userIDBytes, err := store.Get("email/" + email)
	if err != nil {
		return errors.New("not found")
	}

	userID := string(userIDBytes)

	// Delete both the user data and email index
	err1 := store.Delete("user/" + userID)
	err2 := store.Delete("email/" + email)

	if err1 != nil {
		return fmt.Errorf("Error deleting user: %s", userID)
	}
	if err2 != nil {
		return fmt.Errorf("Error deleting email index for: %s", email)
	}

	return nil
}

func (r *UserRepoStore) List(tenantID string, offset, limit int) (UsersListResponse, error) {
	if tenantID == "" {
		return UsersListResponse{}, fmt.Errorf("users.List: tenantID is required")
	}

	store, err := r.getOrCreateStore(tenantID, false)
	if err != nil {
		return UsersListResponse{Users: []*User{}, Total: 0, Offset: offset, Limit: limit}, nil
	}

	keys := store.Keys()
	list := make([]*User, 0, len(keys))

	// Only iterate over user/ keys, not email/ keys
	for _, key := range keys {
		if len(key) < 5 || key[:5] != "user/" {
			continue
		}

		data, err := store.Get(key)
		if err != nil {
			continue
		}

		var user User
		if err := json.Unmarshal(data, &user); err != nil {
			continue
		}

		list = append(list, &user)
	}

	sort.Slice(list, func(i, j int) bool {
		return list[i].ID < list[j].ID
	})

	total := len(list)
	if offset >= total {
		return UsersListResponse{Users: []*User{}, Total: total, Offset: offset, Limit: limit}, nil
	}

	end := offset + limit
	if end > total {
		end = total
	}

	return UsersListResponse{
		Users:  list[offset:end],
		Total:  total,
		Offset: offset,
		Limit:  end - offset,
	}, nil
}

func (r *UserRepoStore) Count(tenantID string) (int, error) {
	if tenantID == "" {
		return 0, fmt.Errorf("users.Count: tenantID is required")
	}

	store, err := r.getOrCreateStore(tenantID, false)
	if err != nil {
		return 0, nil
	}

	// Count only user/ keys, not email/ keys
	count := 0
	for _, key := range store.Keys() {
		if len(key) >= 5 && key[:5] == "user/" {
			count++
		}
	}

	return count, nil
}

func (r *UserRepoStore) SetBlocked(tenantID, email string, blocked bool) error {
	user, err := r.GetByEmail(tenantID, email)
	if err != nil {
		return err
	}
	user.Blocked = blocked
	return r.Upsert(tenantID, user)
}

func (r *UserRepoStore) SetVerified(tenantID, email string, verified bool) error {
	user, err := r.GetByEmail(tenantID, email)
	if err != nil {
		return err
	}
	user.Verified = verified
	return r.Upsert(tenantID, user)
}

func (r *UserRepoStore) SetLoggedIn(tenantID, email string, loggedIn bool) error {
	user, err := r.GetByEmail(tenantID, email)
	if err != nil {
		return err
	}
	user.LoggedIn = loggedIn
	return r.Upsert(tenantID, user)
}

func (r *UserRepoStore) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, store := range r.stores {
		store.Close()
	}
}

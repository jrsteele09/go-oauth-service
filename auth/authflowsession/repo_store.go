package authflowsession

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/jrsteele09/go-kvstore/kvstore"
	"github.com/jrsteele09/go-kvstore/persistence"
)

var _ Repo = (*SessionRepoStore)(nil)

const (
	sessionsSubfolder = "authsession"
	sessionKeyPrefix  = "authdata/"
	codeKeyPrefix     = "code/"
	sessionTTL        = 30 * time.Minute // 30 minutes
	evictionInterval  = time.Minute      // Check for expired sessions every minute
	unloadAfter       = 5 * time.Minute  // Unload data to disk if not accessed for 5 minutes
)

type SessionRepoStore struct {
	store *kvstore.Store
}

func NewRepoStore(basefolder string) (Repo, error) {
	storePath := path.Clean(path.Join(basefolder, sessionsSubfolder))
	if err := os.MkdirAll(storePath, 0755); err != nil {
		return nil, fmt.Errorf("sessions.NewRepoStore: MkdirAll: %w", err)
	}

	fsPersistence, err := persistence.New(storePath)
	if err != nil {
		fmt.Println("Error:", err)
		return nil, fmt.Errorf("sessions.NewRepoStore: %w", err)
	}

	bufferedPersistence, err := persistence.NewBuffer(fsPersistence, 10)
	if err != nil {
		fmt.Println("Error:", err)
		return nil, fmt.Errorf("sessions.NewRepoStore: %w", err)
	}

	kv, err := kvstore.New(kvstore.WithUnloadFrequencyOption(evictionInterval, unloadAfter), kvstore.WithPersistenceOption(bufferedPersistence))
	if err != nil {
		return nil, fmt.Errorf("sessions.NewRepoStore: %w", err)
	}
	return &SessionRepoStore{
		store: kv,
	}, nil
}

func (sr *SessionRepoStore) Upsert(sessionID string, sessionData *AuthData) error {
	sessionData.ID = sessionID

	data, err := json.Marshal(sessionData)
	if err != nil {
		return fmt.Errorf("sessions.Upsert: failed to marshal session data: %w", err)
	}

	key := sessionKeyPrefix + sessionID
	if err := sr.store.Set(key, data); err != nil {
		return fmt.Errorf("sessions.Upsert: failed to set session: %w", err)
	}

	// Set TTL
	if err := sr.store.SetTTL(key, int64(sessionData.TTL.Seconds())); err != nil {
		return fmt.Errorf("sessions.Upsert: failed to set TTL: %w", err)
	}

	return nil
}

func (sr *SessionRepoStore) Delete(sessionID string) error {
	// First get the session to check if it has an auth code
	session, err := sr.Get(sessionID)
	if err != nil {
		return err
	}

	// Delete the session
	key := sessionKeyPrefix + sessionID
	if err := sr.store.Delete(key); err != nil {
		return fmt.Errorf("sessions.Delete: failed to delete session: %w", err)
	}

	// Clean up authorization code mapping if exists
	if session.AuthCode != "" {
		codeKey := codeKeyPrefix + session.AuthCode
		sr.store.Delete(codeKey) // Ignore error if code doesn't exist
	}

	return nil
}

func (sr *SessionRepoStore) Get(sessionID string) (*AuthData, error) {
	key := sessionKeyPrefix + sessionID
	data, err := sr.store.Get(key)
	if err != nil {
		return nil, errors.New("not found")
	}

	var sessionData AuthData
	if err := json.Unmarshal(data, &sessionData); err != nil {
		return nil, fmt.Errorf("sessions.Get: failed to unmarshal session data: %w", err)
	}

	return &sessionData, nil
}

func (sr *SessionRepoStore) UpdateUser(sessionID, email string) error {
	session, err := sr.Get(sessionID)
	if err != nil {
		return err
	}

	session.UserEmail = email
	return sr.Upsert(sessionID, session)
}

func (sr *SessionRepoStore) AssignCodeToSessionID(sessionID, code string, ttl time.Duration) error {
	session, err := sr.Get(sessionID)
	if err != nil {
		return err
	}

	session.AuthCode = code

	// Store the code -> sessionID mapping
	codeKey := codeKeyPrefix + code
	if err := sr.store.Set(codeKey, []byte(sessionID)); err != nil {
		return fmt.Errorf("sessions.AssignCodeToSessionID: failed to set code mapping: %w", err)
	}

	// Set TTL on the code mapping as well
	if err := sr.store.SetTTL(codeKey, int64(sessionTTL.Seconds())); err != nil {
		return fmt.Errorf("sessions.AssignCodeToSessionID: failed to set code TTL: %w", err)
	}

	// Update the session with the auth code
	return sr.Upsert(sessionID, session)
}

func (sr *SessionRepoStore) GetSessionFromAuthCode(code string) (*AuthData, error) {
	codeKey := codeKeyPrefix + code
	data, err := sr.store.Get(codeKey)
	if err != nil {
		return nil, errors.New("not found")
	}

	sessionID := string(data)
	return sr.Get(sessionID)
}

func (sr *SessionRepoStore) Close() {
	sr.store.Close()
}

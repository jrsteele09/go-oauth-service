package adminsession

import (
	"testing"
	"time"
)

func TestInMemoryRepoGetReturnsStoredSession(t *testing.T) {
	repo := NewInMemoryRepo()
	session := Session{
		TenantID:  "system-tenant",
		UserID:    "user-1",
		Email:     "admin@example.com",
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(time.Hour),
	}

	if err := repo.Upsert("session-1", session); err != nil {
		t.Fatalf("Upsert() error = %v", err)
	}

	got, err := repo.Get("session-1")
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if got.UserID != session.UserID || got.TenantID != session.TenantID || got.Email != session.Email {
		t.Fatalf("Get() = %#v, want %#v", got, session)
	}
}

func TestInMemoryRepoGetRejectsExpiredSession(t *testing.T) {
	repo := NewInMemoryRepo()
	session := Session{
		TenantID:  "system-tenant",
		UserID:    "user-1",
		ExpiresAt: time.Now().Add(-time.Minute),
	}

	if err := repo.Upsert("session-1", session); err != nil {
		t.Fatalf("Upsert() error = %v", err)
	}

	if _, err := repo.Get("session-1"); err == nil {
		t.Fatal("Get() error = nil, want expired session error")
	}
}

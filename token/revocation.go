package token

import (
	"sync"
	"time"
)

// RevokedTokenCache interface for managing revoked access tokens
type RevokedTokenCache interface {
	Add(jti string, exp time.Time) error
	IsRevoked(jti string) bool
	Cleanup() // Remove expired entries
}

// InMemoryRevokedTokenCache is a simple in-memory implementation
type InMemoryRevokedTokenCache struct {
	revoked map[string]time.Time
	mu      sync.RWMutex
}

func NewInMemoryRevokedTokenCache() RevokedTokenCache {
	return &InMemoryRevokedTokenCache{
		revoked: make(map[string]time.Time),
	}
}

func (c *InMemoryRevokedTokenCache) Add(jti string, exp time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.revoked[jti] = exp
	return nil
}

func (c *InMemoryRevokedTokenCache) IsRevoked(jti string) bool {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, exists := c.revoked[jti]
	return exists
}

func (c *InMemoryRevokedTokenCache) Cleanup() {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for jti, exp := range c.revoked {
		if now.After(exp) {
			delete(c.revoked, jti)
		}
	}
}

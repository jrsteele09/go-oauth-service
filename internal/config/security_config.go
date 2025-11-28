package config

import "time"

type SecurityConfig interface {
	GetRequirePKCE() bool
	GetMaxSessionAge() time.Duration
	GetEnableRateLimiting() bool
}

type Security struct{}

var _ SecurityConfig = Security{}

func (Security) GetRequirePKCE() bool {
	return false // Currently optional
}

func (Security) GetMaxSessionAge() time.Duration {
	return 30 * time.Minute // Sessions expire after 30 minutes
}

func (Security) GetEnableRateLimiting() bool {
	return false // Not yet implemented
}

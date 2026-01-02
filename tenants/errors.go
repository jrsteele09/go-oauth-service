package tenants

import "errors"

var (
	ErrTenantNotFound     = errors.New("tenant not found")
	ErrInvalidTenant      = errors.New("invalid tenant")
	ErrUnauthorizedTenant = errors.New("unauthorized for tenant")
)

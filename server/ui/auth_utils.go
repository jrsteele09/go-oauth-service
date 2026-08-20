package ui

import (
	"github.com/jrsteele09/go-auth-server/tenants"
	"github.com/jrsteele09/go-auth-server/utils"
)

func (h *UIHandler) tenantFromHost(host string) (*tenants.Tenant, error) {
	return utils.TenantFromHost(host, h.config.GetBaseURL(), h.config.GetSystemTenantID(), h.tenants)
}

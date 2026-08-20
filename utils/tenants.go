package utils

import (
	"fmt"
	"strings"

	"github.com/jrsteele09/go-auth-server/tenants"
)

func TenantFromHost(host, baseurl, systemTenantID string, tenantRepo tenants.Repo) (*tenants.Tenant, error) {
	splitHost := strings.SplitN(host, ":", 2)
	host = splitHost[0]

	domainURL := baseurl
	splitDomain := strings.SplitN(domainURL, "://", 2)

	baseDomainName := splitDomain[0]
	if len(splitDomain) > 0 {
		baseDomainName = splitDomain[1]
	}

	splitBaseDomain := strings.SplitN(baseDomainName, ":", 2)
	baseHostName := splitBaseDomain[0]

	tenantID := strings.Replace(host, baseHostName, "", 1)
	tenantID = strings.Trim(tenantID, ".")

	if tenantID == "" {
		tenantID = systemTenantID
	}

	t, err := tenantRepo.Get(tenantID) // verify tenant exists
	if err != nil {
		return nil, fmt.Errorf("[server tenantHost] unknown tenant: %w", err)
	}

	return t, nil
}

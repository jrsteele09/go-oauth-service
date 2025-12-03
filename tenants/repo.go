package tenants

type TenantsListResponse struct {
	Tenants []*Tenant `json:"tenants"`
	Total   int       `json:"total"`
	Offset  int       `json:"offset"`
	Limit   int       `json:"limit"`
}

type Repo interface {
	Upsert(tenantData *Tenant) error
	Delete(tenantID string) error
	Get(tenantID string) (*Tenant, error)
	List(offset, limit int) (TenantsListResponse, error)
}

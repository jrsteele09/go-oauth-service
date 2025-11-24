package tenants

type Repo interface {
	Upsert(tenantData *Tenant) error
	Delete(tenantID string) error
	Get(tenantID string) (*Tenant, error)
	List(offset, limit int) ([]*Tenant, error)
}

package tenants

type Tenant struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Domain string `json:"domain"`
}

package clients

type Repo interface {
	Upsert(tenantID string, clientData *Client) error
	Delete(tenantID, clientID string) error
	Get(tenantID, clientID string) (*Client, error)
	List(tenantID string, offset, limit int) ([]*Client, error)
}

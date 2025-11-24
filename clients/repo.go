package clients

type Repo interface {
	Upsert(clientData *Client) error
	Delete(clientID string) error
	Get(clientID string) (*Client, error)
	List(offset, limit int) ([]*Client, error)
}

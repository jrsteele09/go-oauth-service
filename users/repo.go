package users

type UsersListResponse struct {
	Users  []*User `json:"users"`
	Total  int     `json:"total"`
	Offset int     `json:"offset"`
	Limit  int     `json:"limit"`
}

type UserRepo interface {
	Upsert(tenantID string, user *User) error
	Delete(tenantID string, email string) error
	GetByEmail(tenantID string, email string) (*User, error)
	GetByID(tenantID string, ID string) (*User, error)
	List(tenantID string, offset, limit int) (UsersListResponse, error)
	SetBlocked(tenantID string, email string, blocked bool) error
	SetVerified(tenantID string, email string, verified bool) error
	SetLoggedIn(tenantID string, email string, loggedIn bool) error
}

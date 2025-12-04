package users

type UsersListResponse struct {
	Users  []*User `json:"users"`
	Total  int     `json:"total"`
	Offset int     `json:"offset"`
	Limit  int     `json:"limit"`
}

type UserRepo interface {
	Upsert(user *User) error
	Delete(email string) error
	GetByEmail(email string) (*User, error)
	GetByID(ID string) (*User, error)
	List(tenantID string, offset, limit int) (UsersListResponse, error)
	SetBlocked(email string, blocked bool) error
	SetVerified(email string, verified bool) error
	SetLoggedIn(email string, loggedIn bool) error
}

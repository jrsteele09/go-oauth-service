package users

type UserRepo interface {
	Upsert(user *User) error
	Delete(email string) error
	GetByEmail(email string) (*User, error)
	GetByID(ID string) (*User, error)
	List(offset, limit int) ([]*User, error)
	SetBlocked(email string, blocked bool) error
	SetVerified(email string, verified bool) error
	SetLoggedIn(email string, loggedIn bool) error
}

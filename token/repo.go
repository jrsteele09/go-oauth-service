package token

type RefreshTokenRepo interface {
	Upsert(refreshToken *RefreshToken) error
	Delete(token string) error
	Get(token string) (*RefreshToken, error)
	GetByUserID(userID string) (*RefreshToken, error)
	List(offset, limit int) ([]*RefreshToken, error)
}

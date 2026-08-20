package authflowsession

import (
	"time"

	"github.com/jrsteele09/go-auth-server/auth/oauthmodel"
)

// AuthData stores OAuth2 flow state
type AuthData struct {
	ID                  string                              // Unique session identifier (UUID)
	TenantID            string                              // Tenant this session belongs to
	UserID              string                              // User ID (set after authentication)
	UserEmail           string                              // User email (set after successful login)
	AuthCode            string                              // Generated after login, exchanged for tokens
	Timestamp           time.Time                           // When session was created
	TTL                 time.Duration                       // Session time-to-live
	AuthorizationParams *oauthmodel.AuthorizationParameters // Original OAuth2 request parameters (for flow sessions)
	StateHash           string                              // Hashed state parameter for CSRF protection
}

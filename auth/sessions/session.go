package sessions

import (
	"time"

	"github.com/jrsteele09/go-auth-server/oauth2"
)

// SessionData stores OAuth2 flow state during the authorization process.
// Sessions are short-lived (typically 15-30 minutes) and track the state between
// the /authorize endpoint, /login, and /token exchange.
type SessionData struct {
	ID                  string                          // Unique session identifier (UUID)
	TenantID            string                          // Tenant this session belongs to
	UserEmail           string                          // Set after successful login
	AuthCode            string                          // Generated after login, exchanged for tokens
	Timestamp           time.Time                       // When session was created
	AuthorizationParams *oauth2.AuthorizationParameters // Original OAuth2 request parameters
	StateHash           string                          // Hashed state parameter for CSRF protection
}

package sessions

import (
	"time"

	"github.com/jrsteele09/go-auth-server/oauth2"
)

// SessionData stores OAuth2 flow state and authenticated session tokens.
// Two types of sessions:
// 1. OAuth flow sessions (short-lived, 15-30 min) - track state during /authorize → /login → /token
// 2. Authenticated sessions (longer-lived, 1hr-30 days) - store tokens after successful auth
type SessionData struct {
	ID                  string                          // Unique session identifier (UUID)
	TenantID            string                          // Tenant this session belongs to
	UserID              string                          // User ID (set after authentication)
	UserEmail           string                          // User email (set after successful login)
	AuthCode            string                          // Generated after login, exchanged for tokens
	Timestamp           time.Time                       // When session was created
	ExpiresAt           time.Time                       // When session expires
	AuthorizationParams *oauth2.AuthorizationParameters // Original OAuth2 request parameters (for flow sessions)
	StateHash           string                          // Hashed state parameter for CSRF protection

	// Tokens (stored for server-side sessions with HTMX/HTML UIs)
	AccessToken  string    // OAuth2 access token (JWT)
	RefreshToken string    // OAuth2 refresh token
	IDToken      string    // OIDC ID token (JWT)
	TokenExpiry  time.Time // When access token expires
}

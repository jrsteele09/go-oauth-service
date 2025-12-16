package server

import (
	"context"
	"net/http"
	"time"

	"github.com/jrsteele09/go-auth-server/internal/utils"
	"github.com/jrsteele09/go-auth-server/server/authflowrepo"
	"github.com/jrsteele09/go-auth-server/tenants"
	"github.com/jrsteele09/go-auth-server/users"
	"golang.org/x/oauth2"
)

// ContextKey is a custom type for context keys to avoid collisions
type ContextKey string

const (
	// ContextKeyUserID stores the authenticated user ID
	ContextKeyUserID ContextKey = "user_id"
	// ContextKeyTenantID stores the tenant ID
	ContextKeyTenantID ContextKey = "tenant_id"
	// ContextKeyClientID stores the authenticated client ID
	ContextKeyClientID ContextKey = "client_id"
	// ContextKeyClaims stores parsed token claims
	ContextKeyClaims ContextKey = "claims"
	// ContextKeyScopes stores the token scopes
	ContextKeyScopes ContextKey = "scopes"
	// ContextKeySession stores the session information
	ContextKeySession ContextKey = "session"
)

// RequireSessionAuth is middleware for HTML/HTMX routes that validates session cookies
// Used for server-rendered UI routes like /admin/dashboard
func (s *Server) RequireSessionAuth() func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// GET THE TENANT
			tenant, err := s.tenantFromHost(r.Host)
			if err != nil {
				http.Error(w, "tenant not found", http.StatusNotFound)
				return
			}

			// GET OIDC CONFIG FOR TENANT
			oidcConfig, err := s.getOidcConfigForTenant(r.Context(), tenant)
			if err != nil {
				http.Error(w, "failed to get OIDC config", http.StatusInternalServerError)
				return
			}

			// GET THE SESSION ID FROM THE COOKIE
			loggedInCookie, err := r.Cookie(loggedInSessionID)
			if err != nil {
				s.redirectToAuthorize(w, r, tenant, oidcConfig)
				return
			}

			sessionID := loggedInCookie.Value

			// RETRIEVE THE SESSION DATA
			loginSessionData, err := s.loginSessions.Get(tenant.ID, sessionID)
			if err != nil {
				s.redirectToAuthorize(w, r, tenant, oidcConfig)
				return
			}

			// RETRIEVE THE SESSION CLIENT
			client, err := s.repos.Clients.Get(tenant.ID, loginSessionData.ClientID)
			if err != nil || client == nil {
				s.redirectToAuthorize(w, r, tenant, oidcConfig)
				return
			}

			token, err := s.auth.IntrospectToken(tenant.ID, loginSessionData.AccessToken, client.ID, client.Secret)
			if err != nil || !token.Active {
				// Token is invalid or expired - try to refresh if we have a refresh token
				if loginSessionData.RefreshToken == "" {
					s.redirectToAuthorize(w, r, tenant, oidcConfig)
					return
				}

				newToken, err := oidcConfig.OAuth2Config.TokenSource(r.Context(), &oauth2.Token{
					AccessToken:  loginSessionData.AccessToken,
					RefreshToken: loginSessionData.RefreshToken,
				}).Token()
				if err != nil {
					s.redirectToAuthorize(w, r, tenant, oidcConfig)
					return
				}

				loginSessionData.AccessToken = newToken.AccessToken
				loginSessionData.RefreshToken = newToken.RefreshToken

				if err := s.loginSessions.Upsert(tenant.ID, sessionID, loginSessionData); err != nil {
					s.redirectToAuthorize(w, r, tenant, oidcConfig)
					return
				}

				// Update cookie with new expiry
				s.SetLoginSessionCookie(w, sessionID, r, int(time.Until(newToken.Expiry).Seconds()))
				if token, err = s.auth.IntrospectToken(tenant.ID, loginSessionData.AccessToken, client.ID, client.Secret); err != nil || token == nil || !token.Active {
					s.redirectToAuthorize(w, r, tenant, oidcConfig)
					return
				}
			}
			// Token is valid - inject context and proceed
			ctx := context.WithValue(r.Context(), ContextKeyUserID, utils.Value(token.Sub))
			ctx = context.WithValue(ctx, ContextKeyTenantID, tenant.ID)
			ctx = context.WithValue(ctx, ContextKeyClaims, token)
			r = r.WithContext(ctx)

			next(w, r)
		}
	}
}

// RequireAdmin is middleware that validates admin/super-admin roles
// Should be chained after RequireSessionAuth to ensure claims are present
func (s *Server) RequireAdmin() func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Get user ID from context (set by RequireSessionAuth)
			userID, ok := r.Context().Value(ContextKeyUserID).(string)
			if !ok || userID == "" {
				http.Error(w, `{"error":"forbidden","error_description":"User not authenticated"}`, http.StatusForbidden)
				return
			}

			// Get tenant ID from context
			tenantID, ok := r.Context().Value(ContextKeyTenantID).(string)
			if !ok || tenantID == "" {
				http.Error(w, `{"error":"forbidden","error_description":"Tenant not found"}`, http.StatusForbidden)
				return
			}

			// Get user from repository
			user, err := s.repos.Users.GetByID(tenantID, userID)
			if err != nil || user == nil {
				http.Error(w, `{"error":"forbidden","error_description":"User not found"}`, http.StatusForbidden)
				return
			}

			if !user.IsSuperAdmin() && !user.HasTenantRole(tenantID, users.RoleTenantAdmin) {
				http.Error(w, `{"error":"forbidden","error_description":"Admin access required"}`, http.StatusForbidden)
				return
			}

			next(w, r)
		}
	}
}

// RequireScope is middleware that validates the token contains specific scopes
func (s *Server) RequireScope(requiredScopes ...string) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			scopes, ok := r.Context().Value(ContextKeyScopes).([]string)
			if !ok {
				http.Error(w, `{"error":"forbidden","error_description":"No scopes found"}`, http.StatusForbidden)
				return
			}

			// Check if token has all required scopes
			scopeMap := make(map[string]bool)
			for _, s := range scopes {
				scopeMap[s] = true
			}

			for _, required := range requiredScopes {
				if !scopeMap[required] {
					http.Error(w, `{"error":"insufficient_scope","error_description":"Token missing required scope: `+required+`"}`, http.StatusForbidden)
					return
				}
			}

			next(w, r)
		}
	}
}

// redirectToAuthorize initiates an OAuth2 authorization code flow with PKCE for admin UI login
func (s *Server) redirectToAuthorize(w http.ResponseWriter, r *http.Request, tenant *tenants.Tenant, oidcConfig OidcConfig) {
	// Clean up any existing session before starting new OAuth flow
	if sessionCookie, err := r.Cookie(loggedInSessionID); err == nil {
		s.loginSessions.Delete(tenant.ID, sessionCookie.Value)
	}

	// Generate state (random string to prevent CSRF)
	state := generateRandomString(32)

	// Generate nonce for ID token replay protection
	nonce := generateRandomString(32)

	// Generate PKCE code verifier
	codeVerifier := generateRandomString(64)

	// Generate PKCE code challenge
	codeChallenge := generateCodeChallenge(codeVerifier)

	// Store state, nonce, and verifier for callback validation
	if err := s.authState.Upsert(state, &authflowrepo.AuthFlowState{TenantID: tenant.ID, CodeVerifier: codeVerifier, Nonce: nonce, ReturnURL: r.URL.Path}); err != nil {
		http.Error(w, "Failed to initiate auth flow", http.StatusInternalServerError)
		return
	}

	// Use standard oauth2 library to build authorization URL
	// This automatically includes the scopes from oidcConfig.OAuth2Config.Scopes
	authURL := oidcConfig.OAuth2Config.AuthCodeURL(
		state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", codeChallenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)

	// Redirect to authorize endpoint
	http.Redirect(w, r, authURL, http.StatusSeeOther)
}

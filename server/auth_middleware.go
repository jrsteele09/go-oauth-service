package server

import (
	"context"
	"encoding/base64"
	"net/http"
	"strings"
	"time"
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
)

// RequireSessionAuth is middleware for HTML/HTMX routes that validates session cookies
// Used for server-rendered UI routes like /admin/dashboard
func (s *Server) RequireSessionAuth() func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Get session cookie
			cookie, err := r.Cookie("session_id")
			if err != nil {
				// No session cookie - redirect to login
				http.Redirect(w, r, "/auth/login?error=Session+expired", http.StatusSeeOther)
				return
			}

			// Get session from repo
			session, err := s.repos.Sessions.Get(cookie.Value)
			if err != nil || session == nil {
				// Invalid or expired session
				http.Redirect(w, r, "/auth/login?error=Invalid+session", http.StatusSeeOther)
				return
			}

			// Check if session has expired
			if session.ExpiresAt.Before(time.Now()) {
				s.repos.Sessions.Delete(cookie.Value)
				http.Redirect(w, r, "/auth/login?error=Session+expired", http.StatusSeeOther)
				return
			}

			// Check if access token needs refresh
			if session.TokenExpiry.Before(time.Now()) && session.RefreshToken != "" {
				// TODO: Implement token refresh logic
				// For now, just redirect to login
				http.Redirect(w, r, "/auth/login?error=Session+expired", http.StatusSeeOther)
				return
			}

			// Inject session info into context
			ctx := context.WithValue(r.Context(), ContextKeyUserID, session.UserID)
			ctx = context.WithValue(ctx, ContextKeyTenantID, session.TenantID)
			ctx = context.WithValue(ctx, "session", session)
			r = r.WithContext(ctx)

			next(w, r)
		}
	}
}

// RequireAuth is middleware that validates a Bearer access token
// Used for API routes that expect OAuth2 tokens in Authorization header
func (s *Server) RequireAuth() func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Extract Bearer token from Authorization header
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				http.Error(w, `{"error":"unauthorized","error_description":"Missing Authorization header"}`, http.StatusUnauthorized)
				return
			}

			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
				http.Error(w, `{"error":"unauthorized","error_description":"Invalid Authorization header format"}`, http.StatusUnauthorized)
				return
			}

			token := parts[1]
			if token == "" {
				http.Error(w, `{"error":"unauthorized","error_description":"Empty token"}`, http.StatusUnauthorized)
				return
			}

			// TODO: Parse and validate JWT token
			// - Verify signature using JWKS
			// - Check expiration (exp claim)
			// - Check issuer (iss claim)
			// - Check audience (aud claim)
			// - Extract sub, tid, scopes, roles

			// Stub: For now, just pass through with empty context
			// In real implementation, parse token and inject claims:
			// claims := parseAndValidateToken(token)
			// ctx := context.WithValue(r.Context(), ContextKeyUserID, claims.Subject)
			// ctx = context.WithValue(ctx, ContextKeyTenantID, claims.TenantID)
			// ctx = context.WithValue(ctx, ContextKeyClaims, claims)
			// ctx = context.WithValue(ctx, ContextKeyScopes, claims.Scopes)
			// r = r.WithContext(ctx)

			// Temporary stub: fail if token != "stub-valid-token"
			if token != "stub-valid-token" {
				http.Error(w, `{"error":"unauthorized","error_description":"Invalid token"}`, http.StatusUnauthorized)
				return
			}

			// Inject stub claims
			ctx := context.WithValue(r.Context(), ContextKeyUserID, "stub-user-123")
			ctx = context.WithValue(ctx, ContextKeyTenantID, "stub-tenant")
			ctx = context.WithValue(ctx, ContextKeyScopes, []string{"openid", "profile", "email"})
			r = r.WithContext(ctx)

			next(w, r)
		}
	}
}

// RequireClientAuth is middleware that validates client credentials
// Supports both HTTP Basic Auth and POST body client_id/client_secret
func (s *Server) RequireClientAuth() func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			var clientID, clientSecret string

			// Try HTTP Basic Auth first
			authHeader := r.Header.Get("Authorization")
			if authHeader != "" {
				parts := strings.SplitN(authHeader, " ", 2)
				if len(parts) == 2 && strings.ToLower(parts[0]) == "basic" {
					decoded, err := base64.StdEncoding.DecodeString(parts[1])
					if err == nil {
						creds := strings.SplitN(string(decoded), ":", 2)
						if len(creds) == 2 {
							clientID = creds[0]
							clientSecret = creds[1]
						}
					}
				}
			}

			// Fallback to POST body
			if clientID == "" {
				if err := r.ParseForm(); err == nil {
					clientID = r.FormValue("client_id")
					clientSecret = r.FormValue("client_secret")
				}
			}

			if clientID == "" || clientSecret == "" {
				w.Header().Set("WWW-Authenticate", `Basic realm="OAuth2 Client Authentication"`)
				http.Error(w, `{"error":"invalid_client","error_description":"Client authentication required"}`, http.StatusUnauthorized)
				return
			}

			// TODO: Validate client credentials against client store
			// client, err := s.repos.ClientRepo.GetByID(r.Context(), clientID)
			// if err != nil || !client.ValidateSecret(clientSecret) {
			//     http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			//     return
			// }

			// Stub: accept any client with clientID != ""
			if clientID == "" {
				http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
				return
			}

			// Inject client ID into context
			ctx := context.WithValue(r.Context(), ContextKeyClientID, clientID)
			r = r.WithContext(ctx)

			next(w, r)
		}
	}
}

// RequireAdmin is middleware that validates admin/super-admin roles
// Should be chained after RequireAuth to ensure claims are present
func (s *Server) RequireAdmin() func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// TODO: Check claims for admin role or super_admin flag
			// claims, ok := r.Context().Value(ContextKeyClaims).(TokenClaims)
			// if !ok || (!claims.SuperAdmin && !slices.Contains(claims.Roles, "admin")) {
			//     http.Error(w, `{"error":"forbidden","error_description":"Admin access required"}`, http.StatusForbidden)
			//     return
			// }

			// Stub: for now, allow all authenticated requests
			next(w, r)
		}
	}
}

// RequireSuperAdmin is middleware that validates super-admin status
func (s *Server) RequireSuperAdmin() func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// TODO: Check claims for super_admin flag
			// claims, ok := r.Context().Value(ContextKeyClaims).(TokenClaims)
			// if !ok || !claims.SuperAdmin {
			//     http.Error(w, `{"error":"forbidden","error_description":"Super admin access required"}`, http.StatusForbidden)
			//     return
			// }

			// Stub: for now, allow all authenticated requests
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

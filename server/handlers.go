package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jrsteele09/go-auth-server/auth/sessions"
	"github.com/jrsteele09/go-auth-server/internal/utils"
	tenant "github.com/jrsteele09/go-auth-server/tenants"
)

// IndexHandler renders the home page
func (s *Server) IndexHandler() http.HandlerFunc {
	tmpl, err := ParseTemplate("index.html")
	if err != nil {
		panic("Failed to parse index template: " + err.Error())
	}

	return func(w http.ResponseWriter, r *http.Request) {
		data := map[string]interface{}{
			"AppName": s.config.GetAppName(),
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = tmpl.Execute(w, data)
	}
}

// LoginPageData contains data for rendering the login page
type LoginPageData struct {
	TenantID   string
	TenantName string
	SessionID  string
	Error      string
	ShowSignUp bool
	Email      string // Preserve email on error
}

// LoginPageHandler serves the login page for a tenant
func (s *Server) LoginPageHandler() http.HandlerFunc {
	// Parse the template once at startup
	tmpl, err := ParseTemplate("login.html")
	if err != nil {
		panic("Failed to parse login template: " + err.Error())
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// Extract tenant ID from subdomain
		// Expected format: tenant-id.localhost:8080 or localhost:8080 (for admin)
		host := r.Host
		var tenantID string
		var isAdmin bool

		// Remove port if present
		if idx := strings.Index(host, ":"); idx != -1 {
			host = host[:idx]
		}

		// Check if subdomain exists
		if strings.Contains(host, ".") {
			// Extract subdomain (everything before the first dot)
			parts := strings.SplitN(host, ".", 2)
			tenantID = parts[0]
		} else {
			// No subdomain, assume admin panel
			tenantID = "admin"
			isAdmin = true
		}

		// Generate or retrieve session ID
		sessionID := r.URL.Query().Get("session_id")
		if sessionID == "" {
			// For now, we'll let the auth service create the session
			// In a real implementation, you might generate a temporary session here
			sessionID = "pending"
		}

		// Get any error message and email from query params
		errorMsg := r.URL.Query().Get("error")
		email := r.URL.Query().Get("email")

		// Prepare template data
		// For now, just display the subdomain as the tenant name (or "Admin" if no subdomain)
		tenantName := tenantID
		if isAdmin {
			tenantName = "Admin"
		}

		data := LoginPageData{
			TenantID:   tenantID,
			TenantName: tenantName,
			SessionID:  sessionID,
			Error:      errorMsg,
			ShowSignUp: false, // TODO: Add AllowSelfRegistration to Tenant config
			Email:      email, // Preserve email on error
		} // Render template
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if err := tmpl.Execute(w, data); err != nil {
			http.Error(w, "Failed to render template", http.StatusInternalServerError)
			return
		}
	}
}

// getTenantDisplayName returns a display name for the tenant
func getTenantDisplayName(t *tenant.Tenant) string {
	if t.Name != "" {
		return t.Name
	}
	// Fallback to ID with some formatting
	return strings.Title(strings.ReplaceAll(t.ID, "-", " "))
}

// LoginHandler processes the login form submission
func (s *Server) LoginHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse form data
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}

		email := r.FormValue("email")
		password := r.FormValue("password")
		remember := r.FormValue("remember") == "on"

		// Validate input
		if email == "" || password == "" {
			redirectWithErrorAndEmail(w, r, "/auth/login", "Email and password are required", email)
			return
		}

		// Look up user by email
		user, err := s.repos.Users.GetByEmail(email)
		if err != nil {
			// Don't reveal if user exists or not
			redirectWithErrorAndEmail(w, r, "/auth/login", "Login failed", email)
			return
		}

		// Check if user is blocked
		if user.Blocked {
			redirectWithErrorAndEmail(w, r, "/auth/login", "Account is blocked. Contact support.", email)
			return
		}

		// Verify password
		if !user.CheckPasswordHash(password, user.PasswordHash) {
			redirectWithErrorAndEmail(w, r, "/auth/login", "Login failed", email)
			return
		}

		// Get user's primary tenant (or system tenant for super admins)
		tenantID := ""
		if len(user.Tenants) > 0 {
			tenantID = user.Tenants[0].TenantID
		}
		if tenantID == "" {
			redirectWithErrorAndEmail(w, r, "/auth/login", "User not assigned to any tenant", email)
			return
		}

		// Generate OAuth2 tokens for this authenticated session
		tokenResponse, err := s.auth.GenerateTokensForUser(user, tenantID, "admin-dashboard", "openid profile email admin")
		if err != nil {
			redirectWithErrorAndEmail(w, r, "/auth/login", "Login failed", email)
			return
		}

		// Create session with tokens stored server-side
		sessionID := uuid.New().String()
		expiresAt := time.Now()
		if remember {
			expiresAt = expiresAt.Add(30 * 24 * time.Hour) // 30 days
		} else {
			expiresAt = expiresAt.Add(1 * time.Hour) // 1 hour
		}

		sessionData := &sessions.SessionData{
			ID:           sessionID,
			TenantID:     tenantID,
			UserID:       user.ID,
			UserEmail:    user.Email,
			Timestamp:    time.Now(),
			ExpiresAt:    expiresAt,
			AccessToken:  *tokenResponse.AccessToken,
			RefreshToken: utils.SafeDeref(tokenResponse.RefreshToken),
			IDToken:      utils.SafeDeref(tokenResponse.IdToken),
			TokenExpiry:  time.Now().Add(time.Duration(tokenResponse.ExpiresIn) * time.Second),
		}

		if err := s.repos.Sessions.Upsert(sessionID, sessionData); err != nil {
			redirectWithError(w, r, "/auth/login", "Failed to create session")
			return
		}

		// Set HTTP-only session cookie
		s.setSessionCookie(w, sessionID, remember)

		// Update last login time
		// TODO: s.repos.Users.UpdateLastLogin(user.ID)

		// Check if password change is required
		if user.PasswordChangeRequired {
			redirectSuccess(w, r, "/auth/change-password?session_id="+sessionID)
			return
		}

		// Redirect based on user role
		if user.IsSuperAdmin() {
			redirectSuccess(w, r, "/admin/dashboard")
			return
		}

		// Default redirect for regular users
		redirectSuccess(w, r, "/")
	}
}

// redirectWithError helper for htmx-aware error redirects
func redirectWithError(w http.ResponseWriter, r *http.Request, path, errorMsg string) {
	fullPath := path + "?error=" + errorMsg
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", fullPath)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, fullPath, http.StatusSeeOther)
}

// redirectWithErrorAndEmail helper for htmx-aware error redirects that preserves email
func redirectWithErrorAndEmail(w http.ResponseWriter, r *http.Request, path, errorMsg, email string) {
	fullPath := path + "?error=" + errorMsg
	if email != "" {
		fullPath += "&email=" + email
	}
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", fullPath)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, fullPath, http.StatusSeeOther)
}

// redirectWithErrorAndSession helper for htmx-aware error redirects that preserves session_id
func redirectWithErrorAndSession(w http.ResponseWriter, r *http.Request, path, errorMsg, sessionID string) {
	fullPath := path + "?error=" + errorMsg
	if sessionID != "" {
		fullPath += "&session_id=" + sessionID
	}
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", fullPath)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, fullPath, http.StatusSeeOther)
}

// redirectSuccess helper for htmx-aware success redirects
func redirectSuccess(w http.ResponseWriter, r *http.Request, path string) {
	if r.Header.Get("HX-Request") == "true" {
		w.Header().Set("HX-Redirect", path)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, path, http.StatusSeeOther)
}

// setSessionCookie sets the session cookie
func (s *Server) setSessionCookie(w http.ResponseWriter, sessionID string, remember bool) {
	maxAge := 3600 // 1 hour default
	if remember {
		maxAge = 30 * 24 * 3600 // 30 days
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session_id",
		Value:    sessionID,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   s.config.GetEnv() == "PROD", // Only secure in production
		SameSite: http.SameSiteLaxMode,
	})
}

// ForgotPasswordHandler serves the forgot password page
func (s *Server) ForgotPasswordHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Forgot Password: Not yet implemented", http.StatusNotImplemented)
	}
}

// SignupHandler serves the signup page
func (s *Server) SignupHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Sign Up: Not yet implemented", http.StatusNotImplemented)
	}
}

// NotFoundHandler handles 404 errors
func (s *Server) NotFoundHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "404 - Page not found", http.StatusNotFound)
	}
}

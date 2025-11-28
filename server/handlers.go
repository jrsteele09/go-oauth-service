package server

import (
	"net/http"
	"strings"

	tenant "github.com/jrsteele09/go-auth-server/tenants"
)

// LoginPageData contains data for rendering the login page
type LoginPageData struct {
	TenantID   string
	TenantName string
	SessionID  string
	Error      string
	ShowSignUp bool
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

		// Get any error message from query params
		errorMsg := r.URL.Query().Get("error")

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
		sessionID := r.FormValue("session_id")

		// TODO: Integrate with auth service
		// For now, return a placeholder response
		_ = email
		_ = password
		_ = sessionID

		// Redirect back to login with error for now
		http.Redirect(w, r, "/auth/login?error=Authentication+not+yet+implemented", http.StatusSeeOther)
	}
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

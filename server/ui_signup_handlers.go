package server

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/jrsteele09/go-auth-server/users"
)

// ValidatePasswordHandler validates password strength via API
func (s *Server) ValidatePasswordHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		password := r.FormValue("new_password")

		if password == "" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			return
		}

		if err := users.ValidatePasswordStrength(password); err != nil {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			// Add class to parent input via HTMX response header
			w.Header().Set("HX-Trigger", fmt.Sprintf(`{"passwordInvalid": "%s"}`, err.Error()))
			fmt.Fprintf(w, `<span class="text-danger"><i class="bi bi-x-circle-fill me-1"></i>%s</span>`, err.Error())
			return
		}

		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("HX-Trigger", `{"passwordValid": ""}`)
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<span class="text-success"><i class="bi bi-check-circle-fill me-1"></i></span>`)
	}
}

// UIPageData is a minimal template model for UI pages
type UIPageData struct {
	TenantID      string
	TenantName    string
	AuthSessionID string // OAuth authorization session ID
	Error         string
	Token         string
	ClientName    string
	Scopes        []string
	Required      bool // Flag for forced password change
}

// ForgotPasswordGetHandler renders the forgot-password page
func (s *Server) ForgotPasswordGetHandler() http.HandlerFunc {
	tmpl, err := ParseTemplate("forgot_password.html")
	if err != nil {
		panic("Failed to parse forgot password template: " + err.Error())
	}
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, err := s.tenantFromHost(r.Host)
		if err != nil {
			http.Error(w, "unknown tenant", http.StatusBadRequest)
			return
		}
		data := UIPageData{
			TenantID:      tenant.ID,
			TenantName:    tenant.Name,
			AuthSessionID: r.URL.Query().Get("session_id"),
			Error:         r.URL.Query().Get("error"),
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = tmpl.Execute(w, data)
	}
}

// SignupPostHandler handles registration form submission (stub)
func (s *Server) SignupPostHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		redirectSuccess(w, r, RouteAuthLogin+"?error=Sign+up+not+yet+implemented")
	}
}

// SignupGetHandler renders the signup page
func (s *Server) SignupGetHandler() http.HandlerFunc {
	tmpl, err := ParseTemplate("signup.html")
	if err != nil {
		panic("Failed to parse signup template: " + err.Error())
	}
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, err := s.tenantFromHost(r.Host)
		if err != nil {
			http.Error(w, "unknown tenant", http.StatusBadRequest)
			return
		}
		data := UIPageData{
			TenantID:      tenant.ID,
			TenantName:    tenant.Name,
			AuthSessionID: r.URL.Query().Get("session_id"),
			Error:         r.URL.Query().Get("error"),
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = tmpl.Execute(w, data)
	}
}

// ForgotPasswordPostHandler handles forgot password submissions (stub)
func (s *Server) ForgotPasswordPostHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		redirectSuccess(w, r, RouteAuthLogin+"?error=Password+reset+email+not+yet+implemented")
	}
}

// ResetPasswordGetHandler renders reset form (stub)
func (s *Server) ResetPasswordGetHandler() http.HandlerFunc {
	tmpl, err := ParseTemplate("reset_password.html")
	if err != nil {
		panic("Failed to parse reset password template: " + err.Error())
	}
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, err := s.tenantFromHost(r.Host)
		if err != nil {
			http.Error(w, "unknown tenant", http.StatusBadRequest)
			return
		}
		data := UIPageData{
			TenantID:      tenant.ID,
			TenantName:    tenant.Name,
			AuthSessionID: r.URL.Query().Get("session_id"),
			Error:         r.URL.Query().Get("error"),
			Token:         r.URL.Query().Get("token"),
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = tmpl.Execute(w, data)
	}
}

// ResetPasswordPostHandler processes reset form (stub)
func (s *Server) ResetPasswordPostHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		redirectSuccess(w, r, RouteAuthLogin+"?error=Password+reset+not+yet+implemented")
	}
}

// VerifyEmailHandler verifies email using a token (stub)
func (s *Server) VerifyEmailHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Verify Email not yet implemented", http.StatusNotImplemented)
	}
}

// ResendVerificationHandler resends a verification email (stub)
func (s *Server) ResendVerificationHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		redirectSuccess(w, r, RouteAuthLogin+"?error=Verification+email+not+yet+implemented")
	}
}

// ConsentGetHandler renders consent page (stub)
func (s *Server) ConsentGetHandler() http.HandlerFunc {
	tmpl, err := ParseTemplate("consent.html")
	if err != nil {
		panic("Failed to parse consent template: " + err.Error())
	}
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, err := s.tenantFromHost(r.Host)
		if err != nil {
			http.Error(w, "unknown tenant", http.StatusBadRequest)
			return
		}
		scopesParam := r.URL.Query().Get("scope")
		scopes := []string{}
		if scopesParam != "" {
			scopes = strings.Fields(scopesParam)
		}
		data := UIPageData{
			TenantID:      tenant.ID,
			TenantName:    tenant.Name,
			AuthSessionID: r.URL.Query().Get("session_id"),
			Error:         r.URL.Query().Get("error"),
			ClientName:    r.URL.Query().Get("client_name"),
			Scopes:        scopes,
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = tmpl.Execute(w, data)
	}
}

// ConsentPostHandler processes consent decision (stub)
func (s *Server) ConsentPostHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		http.Error(w, "Consent submit not yet implemented", http.StatusNotImplemented)
	}
}

// ChangePasswordGetHandler renders the change password page (forced or optional)
func (s *Server) ChangePasswordGetHandler() http.HandlerFunc {
	tmpl, err := ParseTemplate("change_password.html")
	if err != nil {
		panic("Failed to parse change password template: " + err.Error())
	}
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, err := s.tenantFromHost(r.Host)
		if err != nil {
			http.Error(w, "unknown tenant", http.StatusBadRequest)
			return
		}

		// Check if password change is required (enforced) or optional
		required := r.URL.Query().Get("required") == "true"

		data := UIPageData{
			TenantID:   tenant.ID,
			TenantName: tenant.Name,
			Error:      r.URL.Query().Get("error"),
			Required:   required, // Flag to show/hide cancel button
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = tmpl.Execute(w, data)
	}
}

// ChangePasswordPostHandler processes change password form
func (s *Server) ChangePasswordPostHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}

		// Get tenant from host
		tenant, err := s.tenantFromHost(r.Host)
		if err != nil {
			http.Error(w, "Tenant not found", http.StatusBadRequest)
			return
		}

		// Get logged-in session from cookie
		cookie, err := r.Cookie(loggedInSessionID)
		if err != nil || cookie.Value == "" {
			redirectSuccess(w, r, RouteAdminDashboard)
			return
		}

		sessionID := cookie.Value
		loginSession, err := s.loginSessions.Get(tenant.ID, sessionID)
		if err != nil {
			redirectSuccess(w, r, RouteAdminDashboard)
			return
		}

		newPassword := r.FormValue("new_password")
		confirmPassword := r.FormValue("confirm_password")

		// Validate input
		if newPassword == "" || confirmPassword == "" {
			redirectWithError(w, r, RouteChangePassword, "All fields are required")
			return
		}

		if newPassword != confirmPassword {
			redirectWithError(w, r, RouteChangePassword, "passwords do not match")
			return
		}

		// Validate password strength
		if err := users.ValidatePasswordStrength(newPassword); err != nil {
			redirectWithError(w, r, RouteChangePassword, err.Error())
			return
		}

		// Get user from session email
		user, err := s.repos.Users.GetByEmail(tenant.ID, loginSession.Email)
		if err != nil {
			redirectWithError(w, r, RouteChangePassword, "User not found")
			return
		}

		// Hash new password
		newHash, err := users.HashPassword(newPassword)
		if err != nil {
			redirectWithError(w, r, RouteChangePassword, "Failed to hash password")
			return
		}

		// Update user
		user.PasswordHash = newHash
		user.PasswordChangeRequired = false

		if err := s.repos.Users.Upsert(tenant.ID, user); err != nil {
			redirectWithError(w, r, RouteChangePassword, "Failed to update password")
			return
		}

		// Redirect to dashboard after successful password change
		redirectSuccess(w, r, RouteAdminDashboard)
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

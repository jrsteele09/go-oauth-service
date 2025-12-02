package server

import (
	"net/http"
	"strings"
)

// UIPageData is a minimal template model for UI pages
type UIPageData struct {
	TenantID   string
	TenantName string
	SessionID  string
	Error      string
	Token      string
	ClientName string
	Scopes     []string
}

func tenantFromHost(host string) (tenantID string, tenantName string) {
	// strip port
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	if strings.Contains(host, ".") {
		parts := strings.SplitN(host, ".", 2)
		tenantID = parts[0]
	} else {
		tenantID = "admin"
	}
	tenantName = tenantID
	if tenantID == "admin" {
		tenantName = "Admin"
	}
	return
}

// LogoutHandler ends the user session (stub)
func (s *Server) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// TODO: clear cookies/session
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

// ForgotPasswordGetHandler renders the forgot-password page
func (s *Server) ForgotPasswordGetHandler() http.HandlerFunc {
	tmpl, err := ParseTemplate("forgot_password.html")
	if err != nil {
		panic("Failed to parse forgot password template: " + err.Error())
	}
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, tenantName := tenantFromHost(r.Host)
		data := UIPageData{
			TenantID:   tenantID,
			TenantName: tenantName,
			SessionID:  r.URL.Query().Get("session_id"),
			Error:      r.URL.Query().Get("error"),
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
		// TODO: create user
		if r.Header.Get("HX-Request") == "true" {
			w.Header().Set("HX-Redirect", "/auth/login?error=Sign+up+not+yet+implemented")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Redirect(w, r, "/auth/login?error=Sign+up+not+yet+implemented", http.StatusSeeOther)
	}
}

// SignupGetHandler renders the signup page
func (s *Server) SignupGetHandler() http.HandlerFunc {
	tmpl, err := ParseTemplate("signup.html")
	if err != nil {
		panic("Failed to parse signup template: " + err.Error())
	}
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, tenantName := tenantFromHost(r.Host)
		data := UIPageData{
			TenantID:   tenantID,
			TenantName: tenantName,
			SessionID:  r.URL.Query().Get("session_id"),
			Error:      r.URL.Query().Get("error"),
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
		// TODO: send reset email
		if r.Header.Get("HX-Request") == "true" {
			w.Header().Set("HX-Redirect", "/auth/login?error=Password+reset+email+not+yet+implemented")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Redirect(w, r, "/auth/login?error=Password+reset+email+not+yet+implemented", http.StatusSeeOther)
	}
}

// ResetPasswordGetHandler renders reset form (stub)
func (s *Server) ResetPasswordGetHandler() http.HandlerFunc {
	tmpl, err := ParseTemplate("reset_password.html")
	if err != nil {
		panic("Failed to parse reset password template: " + err.Error())
	}
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, tenantName := tenantFromHost(r.Host)
		data := UIPageData{
			TenantID:   tenantID,
			TenantName: tenantName,
			SessionID:  r.URL.Query().Get("session_id"),
			Error:      r.URL.Query().Get("error"),
			Token:      r.URL.Query().Get("token"),
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
		if r.Header.Get("HX-Request") == "true" {
			w.Header().Set("HX-Redirect", "/auth/login?error=Password+reset+not+yet+implemented")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Redirect(w, r, "/auth/login?error=Password+reset+not+yet+implemented", http.StatusSeeOther)
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
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("HX-Request") == "true" {
			w.Header().Set("HX-Redirect", "/auth/login?error=Verification+email+not+yet+implemented")
			w.WriteHeader(http.StatusNoContent)
			return
		}
		http.Redirect(w, r, "/auth/login?error=Verification+email+not+yet+implemented", http.StatusSeeOther)
	}
}

// ConsentGetHandler renders consent page (stub)
func (s *Server) ConsentGetHandler() http.HandlerFunc {
	tmpl, err := ParseTemplate("consent.html")
	if err != nil {
		panic("Failed to parse consent template: " + err.Error())
	}
	return func(w http.ResponseWriter, r *http.Request) {
		tenantID, tenantName := tenantFromHost(r.Host)
		scopesParam := r.URL.Query().Get("scope")
		scopes := []string{}
		if scopesParam != "" {
			scopes = strings.Fields(scopesParam)
		}
		data := UIPageData{
			TenantID:   tenantID,
			TenantName: tenantName,
			SessionID:  r.URL.Query().Get("session_id"),
			Error:      r.URL.Query().Get("error"),
			ClientName: r.URL.Query().Get("client_name"),
			Scopes:     scopes,
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

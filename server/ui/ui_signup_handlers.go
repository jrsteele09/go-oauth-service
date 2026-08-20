package ui

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/jrsteele09/go-auth-server/auth/users"
	"github.com/jrsteele09/go-auth-server/server/ui/adminsession"
	"github.com/jrsteele09/go-auth-server/utils"
)

// ValidatePasswordHandler validates password strength via API.
func (h *UIHandler) ValidatePasswordHandler() http.HandlerFunc {
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
			w.Header().Set("HX-Trigger", fmt.Sprintf(`{"passwordInvalid": "%s"}`, err.Error()))
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `<span class="text-danger">%s</span>`, err.Error())
			return
		}

		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("HX-Trigger", `{"passwordValid": ""}`)
		w.WriteHeader(http.StatusOK)
	}
}

type UIPageData struct {
	TenantID   string
	TenantName string
	Error      string
	Required   bool
}

// ChangePasswordGetHandler renders the forced admin password-change page.
func (h *UIHandler) ChangePasswordGetHandler() http.HandlerFunc {
	tmpl, err := ParseTemplate("change_password.html")
	if err != nil {
		panic("Failed to parse change password template: " + err.Error())
	}
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, err := h.tenantFromHost(r.Host)
		if err != nil {
			http.Error(w, "unknown tenant", http.StatusBadRequest)
			return
		}

		data := UIPageData{
			TenantID:   tenant.ID,
			TenantName: tenant.Name,
			Error:      r.URL.Query().Get("error"),
			Required:   r.URL.Query().Get("required") == "true",
		}
		w.Header().Set("Content-Type", contentTypeHTML)
		_ = tmpl.Execute(w, data)
	}
}

// ChangePasswordPostHandler processes forced admin password changes.
func (h *UIHandler) ChangePasswordPostHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}

		session, ok := r.Context().Value(ContextKeySession).(adminsession.Session)
		if !ok {
			utils.RedirectPage(w, r, RouteAdminLogin)
			return
		}

		newPassword := r.FormValue("new_password")
		confirmPassword := r.FormValue("confirm_password")
		if newPassword == "" || confirmPassword == "" {
			redirectChangePasswordError(w, r, "All fields are required")
			return
		}
		if newPassword != confirmPassword {
			redirectChangePasswordError(w, r, "passwords do not match")
			return
		}
		if err := users.ValidatePasswordStrength(newPassword); err != nil {
			redirectChangePasswordError(w, r, err.Error())
			return
		}

		user, err := h.users.GetByID(session.TenantID, session.UserID)
		if err != nil || user == nil {
			redirectChangePasswordError(w, r, "User not found")
			return
		}

		newHash, err := users.HashPassword(newPassword)
		if err != nil {
			redirectChangePasswordError(w, r, "Failed to hash password")
			return
		}

		user.PasswordHash = newHash
		user.PasswordChangeRequired = false
		if err := h.users.Upsert(session.TenantID, user); err != nil {
			redirectChangePasswordError(w, r, "Failed to update password")
			return
		}

		session.PasswordChangeRequired = false
		if cookie, err := r.Cookie(adminSessionCookieName); err == nil {
			_ = h.adminSessions.Upsert(cookie.Value, session)
		}

		utils.RedirectPage(w, r, RouteAdminDashboard)
	}
}

func redirectChangePasswordError(w http.ResponseWriter, r *http.Request, errorMsg string) {
	utils.RedirectPage(w, r, RouteChangePassword+"?required=true&error="+url.QueryEscape(errorMsg))
}

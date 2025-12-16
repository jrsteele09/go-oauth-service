package server

import (
	"html/template"
	"net/http"
	"strings"
)

// renderAdminPage renders a page with the admin layout
func (s *Server) renderAdminPage(w http.ResponseWriter, r *http.Request, activePage, pageTitle, contentTemplate string) {
	// Get user and tenant info from context (set by RequireSessionAuth middleware)
	userID, _ := r.Context().Value(ContextKeyUserID).(string)
	tenantID, _ := r.Context().Value(ContextKeyTenantID).(string)

	// Load user info
	user, err := s.repos.Users.GetByID(tenantID, userID)
	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Load tenant info
	tenant, err := s.repos.Tenants.Get(tenantID)
	if err != nil {
		http.Error(w, "Tenant not found", http.StatusNotFound)
		return
	}

	// Build display name
	userName := user.Username
	if user.FirstName != "" || user.LastName != "" {
		fullName := strings.TrimSpace(user.FirstName + " " + user.LastName)
		if fullName != "" {
			userName = fullName
		}
	}

	// Check if this is the master tenant
	isMasterTenant := strings.HasPrefix(tenantID, "master-system-tenant") ||
		strings.Contains(tenant.ID, "system") ||
		strings.Contains(strings.ToLower(tenant.Name), "system")

	// Load content template
	contentTmpl, err := ParseTemplate(contentTemplate)
	if err != nil {
		http.Error(w, "Failed to load content template", http.StatusInternalServerError)
		return
	}

	// Render content to string
	var contentBuf strings.Builder
	if err := contentTmpl.Execute(&contentBuf, nil); err != nil {
		http.Error(w, "Failed to render content", http.StatusInternalServerError)
		return
	}

	// Load layout template
	layoutTmpl, err := ParseTemplate("admin_layout.html")
	if err != nil {
		http.Error(w, "Failed to load layout template", http.StatusInternalServerError)
		return
	}

	data := map[string]interface{}{
		"UserID":         userID,
		"UserName":       userName,
		"TenantID":       tenantID,
		"TenantName":     tenant.Name,
		"AppName":        s.config.GetAppName(),
		"ActivePage":     activePage,
		"PageTitle":      pageTitle,
		"IsMasterTenant": isMasterTenant,
		"Content":        template.HTML(contentBuf.String()),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = layoutTmpl.Execute(w, data)
}

// AdminDashboardHandler renders the admin dashboard
func (s *Server) AdminDashboardHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.renderAdminPage(w, r, "dashboard", "Dashboard", "admin_dashboard_content.html")
	}
}

// AdminTenantsListHandler lists all tenants
func (s *Server) AdminTenantsListHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.renderAdminPage(w, r, "tenants", "Tenants", "admin_tenants_content.html")
	}
}

// AdminClientsListHandler lists all clients
func (s *Server) AdminClientsListHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.renderAdminPage(w, r, "clients", "Clients", "admin_clients_content.html")
	}
}

// AdminUsersListHandler lists all users
func (s *Server) AdminUsersListHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.renderAdminPage(w, r, "users", "Users", "admin_users_content.html")
	}
}

// AdminSettingsHandler shows settings page
func (s *Server) AdminSettingsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.renderAdminPage(w, r, "settings", "Settings", "admin_settings_content.html")
	}
}

// AdminProfileHandler shows user profile page
func (s *Server) AdminProfileHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.renderAdminPage(w, r, "", "Profile", "admin_profile_content.html")
	}
}

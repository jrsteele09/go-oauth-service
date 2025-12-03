package server

import (
	"net/http"
)

// AdminDashboardHandler renders the admin dashboard
func (s *Server) AdminDashboardHandler() http.HandlerFunc {
	tmpl, err := ParseTemplate("admin_dashboard.html")
	if err != nil {
		panic("Failed to parse admin dashboard template: " + err.Error())
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// Get user and tenant info from context (set by RequireSessionAuth middleware)
		userID, _ := r.Context().Value(ContextKeyUserID).(string)
		tenantID, _ := r.Context().Value(ContextKeyTenantID).(string)

		// Load user info
		user, err := s.repos.Users.GetByID(userID)
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
			fullName := user.FirstName + " " + user.LastName
			// Trim extra spaces
			userName = fullName
			if len(fullName) > 1 && fullName[0] == ' ' {
				userName = fullName[1:]
			} else if len(fullName) > 1 && fullName[len(fullName)-1] == ' ' {
				userName = fullName[:len(fullName)-1]
			}
		}

		data := map[string]interface{}{
			"UserID":     userID,
			"UserName":   userName,
			"TenantID":   tenantID,
			"TenantName": tenant.Name,
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = tmpl.Execute(w, data)
	}
}

// AdminTenantsListHandler lists all tenants (stub)
func (s *Server) AdminTenantsListHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Admin Tenants List: Not yet implemented", http.StatusNotImplemented)
	}
}

// AdminUsersListHandler lists all users (stub)
func (s *Server) AdminUsersListHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "Admin Users List: Not yet implemented", http.StatusNotImplemented)
	}
}

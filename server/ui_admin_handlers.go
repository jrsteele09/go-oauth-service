package server

import (
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/jrsteele09/go-auth-server/clients"
	"github.com/jrsteele09/go-auth-server/tenants"
)

// renderAdminPage renders a page with the admin layout
func (s *Server) renderAdminPage(w http.ResponseWriter, r *http.Request, activePage, pageTitle, contentTemplate string) {
	s.renderAdminPageWithData(w, r, activePage, pageTitle, contentTemplate, nil)
}

// renderAdminPageWithData renders a page with the admin layout and passes data to the content template
func (s *Server) renderAdminPageWithData(w http.ResponseWriter, r *http.Request, activePage, pageTitle, contentTemplate string, contentData interface{}) {
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
	isMasterTenant := strings.EqualFold(tenantID, s.config.GetSystemTenantID())

	// Load content template
	contentTmpl, err := ParseTemplate(contentTemplate)
	if err != nil {
		http.Error(w, "Failed to load content template", http.StatusInternalServerError)
		return
	}

	// Render content to string
	var contentBuf strings.Builder
	if err := contentTmpl.Execute(&contentBuf, contentData); err != nil {
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
		// Get tenant ID from context
		tenantID, _ := r.Context().Value(ContextKeyTenantID).(string)

		// Get stats from repositories

		// Count tenants - always at least 1 (system tenant)
		tenantCount := 0
		var err error
		if strings.EqualFold(tenantID, s.config.GetSystemTenantID()) {
			if tenantCount, err = s.repos.Tenants.Count(); err != nil {
				http.Error(w, "Failed to get tenant count", http.StatusInternalServerError)
				return
			}
		}

		// Count users in this tenant
		userCount := 0
		if userCount, err = s.repos.Users.Count(tenantID); err != nil {
			http.Error(w, "Failed to get Users count", http.StatusInternalServerError)
			return
		}

		// Count active sessions - simplified (would need session repo method)
		sessionCount := 1 // At least 1 (current session)
		if sessionCount, err = s.repos.RefreshTokens.Count(tenantID); err != nil {
			http.Error(w, "Failed to get sessions count", http.StatusInternalServerError)
			return
		}

		// Count OAuth clients in this tenant
		clientCount := 0
		if clientCount, err = s.repos.Clients.Count(tenantID); err != nil {
			http.Error(w, "Failed to get clients count", http.StatusInternalServerError)
			return
		}

		// Create stats data
		stats := map[string]interface{}{
			"TenantCount":  tenantCount,
			"UserCount":    userCount,
			"SessionCount": sessionCount,
			"ClientCount":  clientCount,
		}

		s.renderAdminPageWithData(w, r, "dashboard", "Dashboard", "admin_dashboard_content.html", stats)
	}
}

// AdminTenantsListHandler lists all tenants (only for system tenant users)
func (s *Server) AdminTenantsListHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get tenant ID from context
		tenantID, _ := r.Context().Value(ContextKeyTenantID).(string)

		// Only system tenant users can manage all tenants
		if !strings.EqualFold(tenantID, s.config.GetSystemTenantID()) {
			http.Error(w, "Forbidden: Only system tenant users can manage tenants", http.StatusForbidden)
			return
		}

		// Fetch all tenants
		tenantsResponse, err := s.repos.Tenants.List(0, 100)
		if err != nil {
			http.Error(w, "Failed to fetch tenants", http.StatusInternalServerError)
			return
		}

		// Ensure tenants list is not nil for template rendering
		tenantsList := tenantsResponse.Tenants
		if tenantsList == nil {
			tenantsList = []*tenants.Tenant{}
		}

		data := map[string]interface{}{
			"Tenants":        tenantsList,
			"SystemTenantID": s.config.GetSystemTenantID(),
		}

		s.renderAdminPageWithData(w, r, "tenants", "Tenants", "admin_tenants_content.html", data)
	}
}

// AdminTenantNewHandler shows the form to create a new tenant
func (s *Server) AdminTenantNewHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get tenant ID from context
		tenantID, _ := r.Context().Value(ContextKeyTenantID).(string)

		// Only system tenant users can create tenants
		if !strings.EqualFold(tenantID, s.config.GetSystemTenantID()) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		data := map[string]interface{}{
			"IsNew": true,
		}

		s.renderAdminPageWithData(w, r, "tenants", "New Tenant", "admin_tenant_form.html", data)
	}
}

// AdminTenantEditHandler shows the form to edit an existing tenant
func (s *Server) AdminTenantEditHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get tenant ID from context
		tenantID, _ := r.Context().Value(ContextKeyTenantID).(string)

		// Only system tenant users can edit tenants
		if !strings.EqualFold(tenantID, s.config.GetSystemTenantID()) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		// Get tenant ID from URL query
		editTenantID := r.URL.Query().Get("id")
		if editTenantID == "" {
			http.Error(w, "Tenant ID required", http.StatusBadRequest)
			return
		}

		// Fetch the tenant
		tenant, err := s.repos.Tenants.Get(editTenantID)
		if err != nil {
			http.Error(w, "Tenant not found", http.StatusNotFound)
			return
		}

		// Get effective expiry values (using defaults if not set)
		accessTokenExpiry := tenant.Config.GetAccessTokenExpiry(s.config.GetDefaultAccessTokenExpiry())
		idTokenExpiry := tenant.Config.GetIDTokenExpiry(s.config.GetDefaultIDTokenExpiry())
		refreshTokenExpiry := tenant.Config.GetRefreshTokenExpiry(s.config.GetDefaultRefreshTokenExpiry())

		data := map[string]interface{}{
			"IsNew":                    false,
			"Tenant":                   tenant,
			"AccessTokenExpiryMinutes": int(accessTokenExpiry.Minutes()),
			"IDTokenExpiryMinutes":     int(idTokenExpiry.Minutes()),
			"RefreshTokenExpiryHours":  int(refreshTokenExpiry.Hours()),
		}

		s.renderAdminPageWithData(w, r, "tenants", "Edit Tenant", "admin_tenant_form.html", data)
	}
}

// AdminTenantSaveHandler handles create/update of tenants
func (s *Server) AdminTenantSaveHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get tenant ID from context
		tenantID, _ := r.Context().Value(ContextKeyTenantID).(string)

		// Only system tenant users can save tenants
		if !strings.EqualFold(tenantID, s.config.GetSystemTenantID()) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `<div class="alert alert-danger">Forbidden: Only system tenant users can manage tenants</div>`)
			return
		}

		// Parse form
		if err := r.ParseForm(); err != nil {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `<div class="alert alert-danger">Invalid form data</div>`)
			return
		}

		newTenantID := r.FormValue("tenant_id")
		name := r.FormValue("name")
		domain := r.FormValue("domain")
		issuer := r.FormValue("issuer")
		audience := r.FormValue("audience")
		isNew := r.FormValue("is_new") == "true"

		// Parse token expiry times
		var accessTokenExpiry, idTokenExpiry, refreshTokenExpiry time.Duration
		if val := r.FormValue("access_token_expiry_minutes"); val != "" {
			if mins, err := time.ParseDuration(val + "m"); err == nil {
				accessTokenExpiry = mins
			}
		}
		if val := r.FormValue("id_token_expiry_minutes"); val != "" {
			if mins, err := time.ParseDuration(val + "m"); err == nil {
				idTokenExpiry = mins
			}
		}
		if val := r.FormValue("refresh_token_expiry_hours"); val != "" {
			if hours, err := time.ParseDuration(val + "h"); err == nil {
				refreshTokenExpiry = hours
			}
		}

		if isNew {
			// Create new tenant using tenants.New
			config := tenants.TenantConfig{
				Issuer:             issuer,
				Audience:           audience,
				AccessTokenExpiry:  accessTokenExpiry,
				IDTokenExpiry:      idTokenExpiry,
				RefreshTokenExpiry: refreshTokenExpiry,
			}

			tenant, err := tenants.New(newTenantID, name, domain, config)
			if err != nil {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, `<div class="alert alert-danger">Failed to create tenant: %s</div>`, err.Error())
				return
			}

			if err := s.repos.Tenants.Upsert(tenant); err != nil {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, `<div class="alert alert-danger">Failed to save tenant: %s</div>`, err.Error())
				return
			}

			if _, err := s.createAdminClient(r.Context(), s.config, tenant.ID); err != nil {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, `<div class="alert alert-danger">Failed to create admin client for tenant: %s</div>`, err.Error())
				return
			}

		} else {
			// Update existing tenant - get it first to preserve keys
			tenant, err := s.repos.Tenants.Get(newTenantID)
			if err != nil {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusNotFound)
				fmt.Fprint(w, `<div class="alert alert-danger">Tenant not found</div>`)
				return
			}

			// Update fields
			tenant.Name = name
			tenant.Domain = domain
			tenant.Config.Issuer = issuer
			tenant.Config.Audience = audience
			tenant.Config.AccessTokenExpiry = accessTokenExpiry
			tenant.Config.IDTokenExpiry = idTokenExpiry
			tenant.Config.RefreshTokenExpiry = refreshTokenExpiry

			if err := s.repos.Tenants.Upsert(tenant); err != nil {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprintf(w, `<div class="alert alert-danger">Failed to update tenant: %s</div>`, err.Error())
				return
			}
		}

		// Return success message with redirect
		w.Header().Set("HX-Redirect", "/admin/tenants")
		w.WriteHeader(http.StatusOK)
	}
}

// AdminClientsListHandler lists all clients
func (s *Server) AdminClientsListHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get tenant ID from context
		tenantID, _ := r.Context().Value(ContextKeyTenantID).(string)

		// Fetch tenant info
		tenant, err := s.repos.Tenants.Get(tenantID)
		if err != nil {
			http.Error(w, "Tenant not found", http.StatusNotFound)
			return
		}

		// Fetch all clients for this tenant
		clientsList, err := s.repos.Clients.List(tenantID, 0, 100)
		if err != nil {
			http.Error(w, "Failed to fetch clients", http.StatusInternalServerError)
			return
		}

		// Ensure clients list is not nil for template rendering
		if clientsList == nil {
			clientsList = []*clients.Client{}
		}

		data := map[string]interface{}{
			"Clients":       clientsList,
			"TenantName":    tenant.Name,
			"AdminClientID": s.config.GetAdminClientID(),
		}

		s.renderAdminPageWithData(w, r, "clients", "Clients", "admin_clients_content.html", data)
	}
}

// AdminClientNewHandler shows the form to create a new client
func (s *Server) AdminClientNewHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data := map[string]interface{}{
			"IsNew": true,
		}
		s.renderAdminPageWithData(w, r, "clients", "Create Client", "admin_client_form.html", data)
	}
}

// AdminClientEditHandler shows the form to edit an existing client
func (s *Server) AdminClientEditHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get tenant ID from context
		tenantID, _ := r.Context().Value(ContextKeyTenantID).(string)

		// Get client ID from query parameter
		editClientID := r.URL.Query().Get("id")
		if editClientID == "" {
			http.Error(w, "Client ID is required", http.StatusBadRequest)
			return
		}

		// Fetch client
		client, err := s.repos.Clients.Get(tenantID, editClientID)
		if err != nil {
			http.Error(w, "Client not found", http.StatusNotFound)
			return
		}

		data := map[string]interface{}{
			"IsNew":  false,
			"Client": client,
		}

		s.renderAdminPageWithData(w, r, "clients", "Edit Client", "admin_client_form.html", data)
	}
}

// AdminClientSaveHandler handles create/update of clients
func (s *Server) AdminClientSaveHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get tenant ID from context
		tenantID, _ := r.Context().Value(ContextKeyTenantID).(string)

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}

		isNew := r.FormValue("is_new") == "true"
		clientID := strings.TrimSpace(r.FormValue("client_id"))
		description := r.FormValue("description")
		clientType := r.FormValue("client_type")
		secret := r.FormValue("secret")

		// Validate client ID has no spaces
		if strings.Contains(clientID, " ") {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `<div class="alert alert-danger">Client ID cannot contain spaces</div>`)
			return
		}

		// Check for duplicate client ID on creation
		if isNew {
			existingClient, _ := s.repos.Clients.Get(tenantID, clientID)
			if existingClient != nil {
				w.Header().Set("Content-Type", "text/html")
				w.WriteHeader(http.StatusBadRequest)
				fmt.Fprint(w, `<div class="alert alert-danger">Client ID already exists</div>`)
				return
			}
		}

		// Validate secret for confidential clients
		if clientType == "confidential" && secret == "" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `<div class="alert alert-danger">Client secret is required for confidential clients</div>`)
			return
		}

		// Parse redirect URIs (one per line)
		redirectURIsText := r.FormValue("redirect_uris")
		var redirectURIs []string
		if redirectURIsText != "" {
			for _, uri := range strings.Split(redirectURIsText, "\n") {
				uri = strings.TrimSpace(uri)
				if uri != "" {
					redirectURIs = append(redirectURIs, uri)
				}
			}
		}

		// Parse scopes (one per line)
		scopesText := r.FormValue("scopes")
		var scopes []string
		if scopesText != "" {
			for _, scope := range strings.Split(scopesText, "\n") {
				scope = strings.TrimSpace(scope)
				if scope != "" {
					scopes = append(scopes, scope)
				}
			}
		}

		client := &clients.Client{
			ID:           clientID,
			Type:         clients.ClientType(clientType),
			Description:  description,
			Secret:       secret,
			TenantID:     tenantID,
			RedirectURIs: redirectURIs,
			Scopes:       scopes,
		}

		if err := s.repos.Clients.Upsert(tenantID, client); err != nil {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `<div class="alert alert-danger">Failed to save client: %s</div>`, err.Error())
			return
		}

		// Return success message with redirect
		w.Header().Set("HX-Redirect", "/admin/clients")
		w.WriteHeader(http.StatusOK)
	}
}

// AdminClientValidateIDHandler validates client ID in real-time
func (s *Server) AdminClientValidateIDHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Failed to parse form", http.StatusBadRequest)
			return
		}

		tenantID, _ := r.Context().Value(ContextKeyTenantID).(string)
		clientID := strings.TrimSpace(r.FormValue("client_id"))
		isNew := r.FormValue("is_new") == "true"

		w.Header().Set("Content-Type", "text/html")

		// Check for spaces
		if strings.Contains(clientID, " ") {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<div class="text-danger"><i class="bi bi-x-circle"></i> Client ID cannot contain spaces</div>`)
			return
		}

		// Check for duplicate on new clients
		if isNew && clientID != "" {
			existingClient, _ := s.repos.Clients.Get(tenantID, clientID)
			if existingClient != nil {
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `<div class="text-danger"><i class="bi bi-x-circle"></i> Client ID already exists</div>`)
				return
			}
		}

		// Valid
		if clientID != "" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<div class="text-success"><i class="bi bi-check-circle"></i> Client ID is available</div>`)
		} else {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<div class="form-text">Unique identifier for this client (e.g., my-web-app)</div>`)
		}
	}
}

// AdminTenantDeleteHandler deletes a tenant
func (s *Server) AdminTenantDeleteHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get tenant ID from context
		tenantID, _ := r.Context().Value(ContextKeyTenantID).(string)

		// Only system tenant users can delete tenants
		if !strings.EqualFold(tenantID, s.config.GetSystemTenantID()) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `<div class="alert alert-danger">Forbidden: Only system tenant users can delete tenants</div>`)
			return
		}

		// Get tenant ID to delete from query parameter
		deleteTenantID := r.URL.Query().Get("id")
		if deleteTenantID == "" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `<div class="alert alert-danger">Tenant ID is required</div>`)
			return
		}

		// Prevent deleting the system tenant
		if strings.EqualFold(deleteTenantID, s.config.GetSystemTenantID()) {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `<div class="alert alert-danger">Cannot delete the system tenant</div>`)
			return
		}

		// Delete the tenant
		if err := s.repos.Tenants.Delete(deleteTenantID); err != nil {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `<div class="alert alert-danger">Failed to delete tenant: %s</div>`, err.Error())
			return
		}

		// Return success
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<div class="alert alert-success">Tenant deleted successfully</div>`)
	}
}

// AdminClientDeleteHandler deletes a client
func (s *Server) AdminClientDeleteHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get tenant ID from context
		tenantID, _ := r.Context().Value(ContextKeyTenantID).(string)

		// Get client ID to delete from query parameter
		clientID := r.URL.Query().Get("id")
		if clientID == "" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, `<div class="alert alert-danger">Client ID is required</div>`)
			return
		}

		// Delete the client
		if err := s.repos.Clients.Delete(tenantID, clientID); err != nil {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `<div class="alert alert-danger">Failed to delete client: %s</div>`, err.Error())
			return
		}

		// Return success
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, `<div class="alert alert-success">Client deleted successfully</div>`)
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

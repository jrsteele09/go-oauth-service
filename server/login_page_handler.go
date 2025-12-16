package server

import (
	"net/http"
	"net/url"

	"github.com/jrsteele09/go-auth-server/oauthmodel"
	"github.com/jrsteele09/go-auth-server/users"
	"github.com/rs/zerolog/log"
)

// LoginPageData contains data for rendering the login page
type LoginPageData struct {
	TenantID      string
	TenantName    string
	AuthSessionID string // OAuth authorization session ID (hidden field in form)
	Error         string
	ShowSignUp    bool
	Email         string // Preserve email on error
}

// LoginPageUIHandler displays the login page (GET /login)
func (s *Server) LoginPageUIHandler() http.HandlerFunc {
	// Parse login template
	loginTmpl, err := ParseTemplate("login.html")
	if err != nil {
		log.Err(err).Msg("Failed to parse login template")
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// Get tenant from host
		tenant, err := s.tenantFromHost(r.Host)
		if err != nil {
			http.Error(w, "Tenant not found", http.StatusBadRequest)
			return
		}

		// Get auth_session_id from cookie (set by /oauth2/authorize)
		cookie, err := r.Cookie(authSessionCookieName)
		if err != nil || cookie.Value == "" {
			http.Error(w, "session not started", http.StatusBadRequest)
			return
		}
		authSessionID := cookie.Value

		// Get optional email and error parameters
		email := r.URL.Query().Get("email")
		errorMsg := r.URL.Query().Get("error")

		// Parse login template
		data := LoginPageData{
			TenantID:      tenant.ID,
			TenantName:    tenant.Name,
			AuthSessionID: authSessionID,
			Error:         errorMsg,
			ShowSignUp:    false, // TODO: Add AllowSelfRegistration to Tenant config
			Email:         email,
		}

		w.Header().Set("Content-Type", contentTypeHTML)
		if err := loginTmpl.Execute(w, data); err != nil {
			log.Err(err).Msg("Failed to render login template")
			http.Error(w, "Failed to render login page", http.StatusInternalServerError)
		}
	}
}

// LoginSubmissionHandler processes the login form submission
func (s *Server) LoginSubmissionHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get tenant from host (validates tenant exists)
		tenant, err := s.tenantFromHost(r.Host)
		if err != nil {
			http.Error(w, "Tenant not found", http.StatusBadRequest)
			return
		}

		// Parse form data
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}

		authSessionID := r.FormValue(authSessionCookieName)
		email := r.FormValue("email")
		password := r.FormValue("password")

		// Validate input
		if authSessionID == "" {
			http.Error(w, "Missing authorization session", http.StatusBadRequest)
			return
		}

		if email == "" || password == "" {
			s.renderLoginError(w, r, tenant.ID, tenant.Name, authSessionID, "Email and password are required", email)
			return
		}

		// Define OAuth redirect callback
		oauthRedirect := func(redirectURI string, responseMode oauthmodel.ResponseModeType, authCode string, state string) {
			if err := callbackRedirect(w, r, redirectURI, responseMode, authCode, state); err != nil {
				http.Error(w, "Failed to redirect to client: "+err.Error(), http.StatusInternalServerError)
			}
		}

		// Define MFA redirect callback (if MFA is required)
		mfaRedirect := func(mfaURL string, mfaType users.MFAuthType, state string) {
			// // Redirect to MFA page with session preserved
			// redirectURL := fmt.Sprintf("/auth/mfa?auth_session_id=%s&mfa_type=%s", authSessionID, mfaType)
			// if state != "" {
			// 	redirectURL += "&state=" + state
			// }
			// http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		}

		// Call authorization service Login - it will validate credentials and redirect
		if err := s.auth.Login(authSessionID, email, password, oauthRedirect, mfaRedirect); err != nil {
			s.renderLoginError(w, r, tenant.ID, tenant.Name, authSessionID, "Invalid email or password", email)
			return
		}

		// Success - the oauthRedirect or mfaRedirect callback has already handled the response
	}
}

func (s *Server) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		redirect := func() {
			s.SetLoginSessionCookie(w, loggedInSessionID, r, -1) // Delete cookie
			redirectSuccess(w, r, "/")
		}

		// Get tenant from host (validates tenant exists)
		tenant, err := s.tenantFromHost(r.Host)
		if err != nil {
			http.Error(w, "Logout: Invalid tenant", http.StatusBadRequest)
			return
		}

		cookie, err := r.Cookie(loggedInSessionID)
		if err != nil || cookie.Value == "" {
			redirect()
			return
		}
		sessionID := cookie.Value

		loginSessionData, err := s.loginSessions.Get(tenant.ID, sessionID)
		if err != nil {
			log.Err(err).Msg("Logout: Invalid session")
			redirect()
			return
		}
		// Get OIDC config to find revocation endpoint
		oidcConfig, err := s.getOidcConfigForTenant(r.Context(), tenant)
		if err != nil {
			log.Err(err).Msg("Logout: Failed to get OIDC config for token revocation")
			redirect()
		}

		// Revocation endpoint is at issuer + RouteOAuth2Revoke
		revokeURL := tenant.Config.Issuer + RouteOAuth2Revoke

		// Helper to revoke a token
		revokeToken := func(token, tokenTypeHint string) {
			form := url.Values{}
			form.Set("token", token)
			form.Set("token_type_hint", tokenTypeHint)
			form.Set("client_id", oidcConfig.OAuth2Config.ClientID)
			form.Set("client_secret", oidcConfig.OAuth2Config.ClientSecret)

			resp, err := http.PostForm(revokeURL, form)
			if err != nil {
				log.Err(err).Str("token_type", tokenTypeHint).Msg("Failed to revoke token")
			} else {
				resp.Body.Close()
			}
		}

		// Revoke refresh token if present
		if loginSessionData.RefreshToken != "" {
			revokeToken(loginSessionData.RefreshToken, "refresh_token")
		}

		// Revoke access token if present
		if loginSessionData.AccessToken != "" {
			revokeToken(loginSessionData.AccessToken, "access_token")
		}

		if err := s.loginSessions.Delete(tenant.ID, sessionID); err != nil {
			log.Err(err).Msg("Failed to delete login session")
		}

		redirect()
	}
}

// renderLoginError redirects to login page with an error message
func (s *Server) renderLoginError(w http.ResponseWriter, r *http.Request, tenantID, tenantName, authSessionID, errorMsg, email string) {
	// Build redirect URL with error and email parameters
	redirectURL := RouteLogin + "?error=" + url.QueryEscape(errorMsg)
	if email != "" {
		redirectURL += "&email=" + url.QueryEscape(email)
	}

	redirectSuccess(w, r, redirectURL)
}

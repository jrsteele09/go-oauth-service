package server

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/jrsteele09/go-auth-server/oauth2"
)

// WellKnownOpenIDConfigHandler serves the OIDC discovery document
func (s *Server) WellKnownOpenIDConfigHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get tenant ID from subdomain
		tenantID := extractTenantID(r)

		// Build issuer URL from request
		issuer := r.URL.Scheme + "://" + r.Host
		if issuer == "://" {
			// Scheme not set in URL, check X-Forwarded-Proto header
			if proto := r.Header.Get("X-Forwarded-Proto"); proto != "" {
				issuer = proto + "://" + r.Host
			} else {
				issuer = "https://" + r.Host
			}
		}

		// Get tenant configuration if tenant ID is available
		if tenantID != "" {
			tenant, err := s.repos.Tenants.Get(tenantID)
			if err == nil && tenant.Config.Issuer != "" {
				issuer = tenant.Config.Issuer
			}
		}

		// Build full URLs for endpoints
		baseURL := issuer

		resp := map[string]any{
			"issuer":                 issuer,
			"authorization_endpoint": baseURL + "/oauth2/authorize",
			"token_endpoint":         baseURL + "/oauth2/token",
			"userinfo_endpoint":      baseURL + "/userinfo",
			"jwks_uri":               baseURL + "/.well-known/jwks.json",
			"revocation_endpoint":    baseURL + "/oauth2/revoke",
			"introspection_endpoint": baseURL + "/oauth2/introspect",
			"end_session_endpoint":   baseURL + "/oauth2/logout",

			// Supported response types
			"response_types_supported": []string{"code"},
			"response_modes_supported": []string{"query"}, // Subject types
			"subject_types_supported":  []string{"public"},

			// Signing algorithms
			"id_token_signing_alg_values_supported": []string{"RS256"},

			// Scopes
			"scopes_supported": []string{
				"openid",         // Returns ID token
				"profile",        // Returns name, given_name, family_name
				"email",          // Returns email, email_verified
				"offline_access", // Returns refresh token
				// Authorization scopes
				"admin",        // Tenant admin - manage users/clients within assigned tenant(s)
				"system:admin", // System admin - manage all tenants and system configuration
			}, // Token endpoint auth methods

			"token_endpoint_auth_methods_supported": []string{
				"client_secret_post", // Credentials in POST body
				"none",               // For public clients with PKCE
			}, // Grant types

			"grant_types_supported": []string{
				"authorization_code",
				"refresh_token",
				"client_credentials",
			},

			// PKCE support
			"code_challenge_methods_supported": []string{"S256", "plain"},

			// Claims returned by /userinfo endpoint
			"claims_supported": []string{
				"sub",                // User ID
				"email",              // User email
				"email_verified",     // Email verification status
				"given_name",         // First name
				"family_name",        // Last name
				"preferred_username", // Username
			},

			// UI locales		"ui_locales_supported": []string{"en-US", "en"},

			// Claims parameter supported
			"claims_parameter_supported":      false,
			"request_parameter_supported":     false,
			"request_uri_parameter_supported": false,
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// JWKsHandler returns the JSON Web Key Set used to validate tokens
func (s *Server) JWKsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get tenant ID from subdomain or default to system tenant
		tenantID := extractTenantID(r)

		// Get JWKS from authorization service
		jwks, err := s.auth.GetJWKS(tenantID)
		if err != nil {
			http.Error(w, "Failed to get JWKS: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour
		_ = json.NewEncoder(w).Encode(jwks)
	}
}

// OAuth2AuthorizeHandler begins the authorization flow
func (s *Server) OAuth2AuthorizeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse authorization parameters from query string
		params, err := parseAuthorizationParameters(r)
		if err != nil {
			http.Error(w, "Invalid authorization request: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Define login redirect callback
		loginRedirect := func(sessionID string) {
			// Redirect to login page with session_id to track OAuth flow
			loginURL := "/auth/login?session_id=" + sessionID
			http.Redirect(w, r, loginURL, http.StatusSeeOther)
		}

		// Define OAuth redirect callback
		oauthRedirect := func(redirectURI string, responseMode oauth2.ResponseModeType, authCode string, state string) {
			// Build redirect URL with authorization code
			separator := "?"
			if strings.Contains(redirectURI, "?") {
				separator = "&"
			}
			fullRedirectURI := redirectURI + separator + "code=" + authCode
			if state != "" {
				fullRedirectURI += "&state=" + state
			}
			http.Redirect(w, r, fullRedirectURI, http.StatusSeeOther)
		}

		// Call authorization service
		if err := s.auth.Authorize(params, loginRedirect, oauthRedirect); err != nil {
			http.Error(w, "Authorization failed: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
}

// OAuth2TokenHandler exchanges code/credentials for tokens
func (s *Server) OAuth2TokenHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse token request from form data
		if err := r.ParseForm(); err != nil {
			writeJSONError(w, "invalid_request", "Failed to parse form data", http.StatusBadRequest)
			return
		}

		tokenReq := oauth2.TokenRequest{
			ClientID:     r.FormValue("client_id"),
			ClientSecret: r.FormValue("client_secret"),
			Code:         r.FormValue("code"),
			CodeVerifier: r.FormValue("code_verifier"),
			RefreshToken: r.FormValue("refresh_token"),
		}

		// Call token service
		tokenResponse, err := s.auth.Token(tokenReq)
		if err != nil {
			writeJSONError(w, "invalid_grant", err.Error(), http.StatusBadRequest)
			return
		}

		// Return token response
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		_ = json.NewEncoder(w).Encode(tokenResponse)
	}
}

// OAuth2IntrospectHandler introspects tokens
func (s *Server) OAuth2IntrospectHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse form data
		if err := r.ParseForm(); err != nil {
			writeJSONError(w, "invalid_request", "Failed to parse form data", http.StatusBadRequest)
			return
		}

		token := r.FormValue("token")
		clientID := r.FormValue("client_id")
		clientSecret := r.FormValue("client_secret")

		if token == "" {
			writeJSONError(w, "invalid_request", "token parameter is required", http.StatusBadRequest)
			return
		}

		// Call introspection service
		introspection, err := s.auth.IntrospectToken(token, clientID, clientSecret)
		if err != nil {
			writeJSONError(w, "server_error", err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(introspection)
	}
}

// OAuth2RevokeHandler revokes tokens
func (s *Server) OAuth2RevokeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		// Parse form data
		if err := r.ParseForm(); err != nil {
			writeJSONError(w, "invalid_request", "Failed to parse form data", http.StatusBadRequest)
			return
		}

		token := r.FormValue("token")
		tokenTypeHint := r.FormValue("token_type_hint")
		clientID := r.FormValue("client_id")
		clientSecret := r.FormValue("client_secret")

		if token == "" {
			writeJSONError(w, "invalid_request", "token parameter is required", http.StatusBadRequest)
			return
		}

		// Call revocation service
		if err := s.auth.RevokeToken(token, tokenTypeHint, clientID, clientSecret); err != nil {
			writeJSONError(w, "invalid_client", err.Error(), http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// UserInfoHandler returns information about the user
func (s *Server) UserInfoHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract access token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeJSONError(w, "invalid_token", "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			writeJSONError(w, "invalid_token", "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		accessToken := parts[1]

		// Call userinfo service
		userInfo, err := s.auth.UserInfo(accessToken)
		if err != nil {
			writeJSONError(w, "invalid_token", err.Error(), http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(userInfo)
	}
}

// OAuth2LogoutHandler logs a user out
func (s *Server) OAuth2LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Extract access token from Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			writeJSONError(w, "invalid_token", "Missing Authorization header", http.StatusUnauthorized)
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			writeJSONError(w, "invalid_token", "Invalid Authorization header format", http.StatusUnauthorized)
			return
		}

		accessToken := parts[1]

		// Get refresh token from request body or query
		refreshToken := r.URL.Query().Get("refresh_token")
		if refreshToken == "" && r.Method == http.MethodPost {
			_ = r.ParseForm()
			refreshToken = r.FormValue("refresh_token")
		}

		// Call logout service
		if err := s.auth.Logout(accessToken, refreshToken); err != nil {
			writeJSONError(w, "server_error", err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// OAuth2DeviceCodeHandler starts a device flow (stub)
func (s *Server) OAuth2DeviceCodeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "not_implemented"})
	}
}

// OAuth2PARHandler handles Pushed Authorization Requests (stub)
func (s *Server) OAuth2PARHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{"request_uri": "urn:example:request:stub", "expires_in": 60})
	}
}

// Helper functions

// parseAuthorizationParameters extracts and validates OAuth2 authorization parameters from request
func parseAuthorizationParameters(r *http.Request) (*oauth2.AuthorizationParameters, error) {
	params := &oauth2.AuthorizationParameters{
		ClientID:            r.URL.Query().Get("client_id"),
		ResponseType:        oauth2.ResponseType(r.URL.Query().Get("response_type")),
		RedirectURI:         r.URL.Query().Get("redirect_uri"),
		Scope:               r.URL.Query().Get("scope"),
		State:               r.URL.Query().Get("state"),
		CodeChallenge:       r.URL.Query().Get("code_challenge"),
		CodeChallengeMethod: oauth2.CodeMethodType(r.URL.Query().Get("code_challenge_method")),
		Nonce:               r.URL.Query().Get("nonce"),
	}

	// Set default response mode if not specified
	if r.URL.Query().Get("response_mode") != "" {
		params.ResponseMode = oauth2.ResponseModeType(r.URL.Query().Get("response_mode"))
	}

	return params, nil
}

// extractTenantID gets tenant ID from subdomain or returns default
func extractTenantID(r *http.Request) string {
	host := r.Host
	// Remove port if present
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// Check if subdomain exists
	if strings.Contains(host, ".") {
		parts := strings.SplitN(host, ".", 2)
		return parts[0]
	}

	// Default to first system tenant (will be resolved by auth service)
	return ""
}

// writeJSONError writes an OAuth2 error response
func writeJSONError(w http.ResponseWriter, errorCode, description string, statusCode int) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errorCode,
		"error_description": description,
	})
}

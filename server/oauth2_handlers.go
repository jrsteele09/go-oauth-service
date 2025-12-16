package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/jrsteele09/go-auth-server/oauthmodel"
	"github.com/rs/zerolog/log"
)

const (
	contentTypeHTML = "text/html; charset=utf-8"
	contentTypeJSON = "application/json; charset=utf-8"
)

// WellKnownOpenIDConfig serves the OIDC discovery document
func (s *Server) WellKnownOpenIDConfig() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get tenant ID from subdomain
		tenant, err := s.tenantFromHost(r.Host)
		if err != nil {
			http.Error(w, "unknown tenant", http.StatusBadRequest)
			return
		}

		// Build full URLs for endpoints
		baseURL := tenant.Config.Issuer

		resp := map[string]any{
			"issuer":                 baseURL,
			"authorization_endpoint": baseURL + RouteOAuth2Authorize,
			"token_endpoint":         baseURL + RouteOAuth2Token,
			"userinfo_endpoint":      baseURL + RouteUserInfo,
			"jwks_uri":               baseURL + RouteWellKnownJWKS,
			"revocation_endpoint":    baseURL + RouteOAuth2Revoke,
			"introspection_endpoint": baseURL + RouteOAuth2Introspect,
			"end_session_endpoint":   baseURL + RouteOAuth2Logout,

			// Supported response types
			"response_types_supported": []string{"code"},
			"response_modes_supported": []string{"query", "fragment", "form_post"},
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
			},

			// Token endpoint auth methods
			"token_endpoint_auth_methods_supported": []string{
				"client_secret_post", // Credentials in POST body
				"none",               // For public clients with PKCE
			},

			// Grant types
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

			// UI locales
			"ui_locales_supported": []string{"en-US", "en"},

			// Claims parameter supported
			"claims_parameter_supported":      false,
			"request_parameter_supported":     false,
			"request_uri_parameter_supported": false,
		}

		w.Header().Set("Content-Type", contentTypeJSON)
		w.Header().Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// JWKS returns the JSON Web Key Set used to validate tokens
func (s *Server) JWKS() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, err := s.tenantFromHost(r.Host)
		if err != nil {
			http.Error(w, "unknown tenant", http.StatusBadRequest)
			return
		}

		// Get JWKS from authorization service
		jwks, err := s.auth.GetJWKS(tenant.ID)
		if err != nil {
			http.Error(w, "Failed to get JWKS: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", contentTypeJSON)
		w.Header().Set("Cache-Control", "public, max-age=3600") // Cache for 1 hour
		_ = json.NewEncoder(w).Encode(jwks)
	}
}

// Authorize begins the authorization flow
func (s *Server) Authorize() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse authorization parameters from query string
		tenant, err := s.tenantFromHost(r.Host)
		if err != nil {
			http.Error(w, "unknown tenant", http.StatusBadRequest)
			return
		}
		params, err := parseAuthorizationParameters(tenant.ID, r)
		if err != nil {
			http.Error(w, "Invalid authorization request: "+err.Error(), http.StatusBadRequest)
			return
		}

		// Define login redirect callback - redirects to login page with authSessionID
		loginRedirect := func(authSessionID, loginURL string) {
			s.SetAuthSessionCookie(w, authSessionID, r) // Set in cookie so the session id doesn't appear in the URL

			// Build redirect URL with optional email parameter
			redirectURL := loginURL
			if email := r.URL.Query().Get("email"); email != "" {
				redirectURL += "?email=" + url.QueryEscape(email)
			}

			http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		}

		// Define OAuth redirect callback
		oauthRedirect := func(redirectURI string, responseMode oauthmodel.ResponseModeType, authCode string, state string) {
			if err := callbackRedirect(w, r, redirectURI, responseMode, authCode, state); err != nil {
				http.Error(w, "Failed to redirect to client: "+err.Error(), http.StatusInternalServerError)
			}
		}

		// Call authorization service
		if err := s.auth.Authorize(params, loginRedirect, oauthRedirect); err != nil {
			http.Error(w, "Authorization failed: "+err.Error(), http.StatusBadRequest)
			return
		}

	}
}

// Token exchanges code/credentials for tokens
func (s *Server) Token() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, err := s.tenantFromHost(r.Host)
		if err != nil {
			http.Error(w, "unknown tenant", http.StatusBadRequest)
			return
		}

		// Parse token request from form data
		if err := r.ParseForm(); err != nil {
			writeJSONError(w, "invalid_request", "Failed to parse form data", http.StatusBadRequest)
			return
		}

		tokenReq := oauthmodel.TokenRequest{
			TenantID:     tenant.ID,
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
		w.Header().Set("Content-Type", contentTypeJSON)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		_ = json.NewEncoder(w).Encode(tokenResponse)
	}
}

// Introspect introspects tokens
func (s *Server) Introspect() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, err := s.tenantFromHost(r.Host)
		if err != nil {
			http.Error(w, "unknown tenant", http.StatusBadRequest)
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
		introspection, err := s.auth.IntrospectToken(tenant.ID, token, clientID, clientSecret)
		if err != nil {
			writeJSONError(w, "server_error", err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", contentTypeJSON)
		_ = json.NewEncoder(w).Encode(introspection)
	}
}

// Revoke revokes tokens
func (s *Server) Revoke() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, err := s.tenantFromHost(r.Host)
		if err != nil {
			http.Error(w, "unknown tenant", http.StatusBadRequest)
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
		if err := s.auth.RevokeToken(tenant.ID, token, tokenTypeHint, clientID, clientSecret); err != nil {
			writeJSONError(w, "invalid_client", err.Error(), http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// UserInfo returns information about the user
func (s *Server) UserInfo() http.HandlerFunc {
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

		w.Header().Set("Content-Type", contentTypeJSON)
		_ = json.NewEncoder(w).Encode(userInfo)
	}
}

// Helper functions

// callbackRedirect sends the authorization code to the client's redirect URI
// using the specified response mode (query, fragment, or form_post).
func callbackRedirect(w http.ResponseWriter, r *http.Request, callbackURI string, responseMode oauthmodel.ResponseModeType, authCode string, state string) error {
	// Parse callback URI
	u, err := url.Parse(callbackURI)
	if err != nil {
		return fmt.Errorf("[callbackRedirect] invalid redirect URI: %w", err)
	}

	// Handle different response modes per OAuth2 spec
	switch responseMode {
	case oauthmodel.FragmentResponseMode:
		// Fragment mode: append to URL fragment (after #) and redirect user's browser
		params := url.Values{}
		params.Set("code", authCode)
		if state != "" {
			params.Set("state", state)
		}
		u.Fragment = params.Encode()
		http.Redirect(w, r, u.String(), http.StatusSeeOther)

	case oauthmodel.FormPostResponseMode:
		// Form post mode: return auto-submitting HTML form that POSTs in user's browser
		// Per OAuth 2.0 Form Post Response Mode spec
		formPostTmpl, err := ParseTemplate("form_post.html")
		if err != nil {
			log.Err(err).Msg("Failed to parse form_post template")
		}

		w.Header().Set("Content-Type", contentTypeHTML)
		w.WriteHeader(http.StatusOK)

		data := struct {
			RedirectURI string
			Code        string
			State       string
		}{
			RedirectURI: u.String(),
			Code:        authCode,
			State:       state,
		}
		_ = formPostTmpl.Execute(w, data)

	default: // QueryResponseMode or empty (default)
		// Query mode: append to query string and redirect user's browser
		q := u.Query()
		q.Set("code", authCode)
		if state != "" {
			q.Set("state", state)
		}
		u.RawQuery = q.Encode()
		http.Redirect(w, r, u.String(), http.StatusSeeOther)
	}
	return nil
}

// parseAuthorizationParameters extracts and validates OAuth2 authorization parameters from request
func parseAuthorizationParameters(tenantID string, r *http.Request) (*oauthmodel.AuthorizationParameters, error) {
	params := &oauthmodel.AuthorizationParameters{
		TenantID:            tenantID,
		ClientID:            r.URL.Query().Get("client_id"),
		ResponseType:        oauthmodel.ResponseType(r.URL.Query().Get("response_type")),
		RedirectURI:         r.URL.Query().Get("redirect_uri"),
		Scope:               r.URL.Query().Get("scope"),
		State:               r.URL.Query().Get("state"),
		CodeChallenge:       r.URL.Query().Get("code_challenge"),
		CodeChallengeMethod: oauthmodel.CodeMethodType(r.URL.Query().Get("code_challenge_method")),
		Nonce:               r.URL.Query().Get("nonce"),
	}

	// Set default response mode if not specified
	if r.URL.Query().Get("response_mode") != "" {
		params.ResponseMode = oauthmodel.ResponseModeType(r.URL.Query().Get("response_mode"))
	}

	return params, nil
}

// writeJSONError writes an OAuth2 error response
func writeJSONError(w http.ResponseWriter, errorCode, description string, statusCode int) {
	w.Header().Set("Content-Type", contentTypeJSON)
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errorCode,
		"error_description": description,
	})
}

package oauth2

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jrsteele09/go-auth-server/auth"
	"github.com/jrsteele09/go-auth-server/auth/oauthmodel"
	"github.com/jrsteele09/go-auth-server/config"
	"github.com/jrsteele09/go-auth-server/tenants"
)

const (
	RouteWellKnownOpenIDConfig = "/.well-known/openid-configuration"
	RouteWellKnownJWKS         = "/.well-known/jwks.json"
	RouteOAuth2Authorize       = "/oauth2/authorize"
	RouteOAuth2Token           = "/oauth2/token"
	RouteOAuth2Introspect      = "/oauth2/introspect"
	RouteOAuth2Revoke          = "/oauth2/revoke"
	RouteUserInfo              = "/userinfo"
	RouteCallback              = "/callback"
)

const (
	contentTypeJSON = "application/json; charset=utf-8"
)

type Handler struct {
	auth           *auth.AuthorizationService
	config         config.CorsConfig
	tenantFromHost func(host string) (*tenants.Tenant, error)
}

func NewHandler(
	authService *auth.AuthorizationService,
	config config.CorsConfig,
	tenantFromHost func(host string) (*tenants.Tenant, error),
) *Handler {
	return &Handler{
		auth:           authService,
		config:         config,
		tenantFromHost: tenantFromHost,
	}
}

func (h *Handler) InitRoutes(register func(pattern string, handler http.Handler)) {
	register("GET "+RouteWellKnownOpenIDConfig, http.HandlerFunc(chainMiddleware(h.WellKnownOpenIDConfig(), h.apiMiddleware()...)))
	register("GET "+RouteWellKnownJWKS, http.HandlerFunc(chainMiddleware(h.JWKS(), h.apiMiddleware()...)))
	register("GET "+RouteOAuth2Authorize, http.HandlerFunc(chainMiddleware(h.Authorize(), h.apiMiddleware()...)))
	register("POST "+RouteOAuth2Token, http.HandlerFunc(chainMiddleware(h.Token(), h.apiMiddleware()...)))
	register("GET "+RouteUserInfo, http.HandlerFunc(chainMiddleware(h.UserInfo(), h.apiMiddleware()...)))
	register("POST "+RouteOAuth2Introspect, http.HandlerFunc(chainMiddleware(h.Introspect(), h.apiMiddleware()...)))
	register("POST "+RouteOAuth2Revoke, http.HandlerFunc(chainMiddleware(h.Revoke(), h.apiMiddleware()...)))
}

// WellKnownOpenIDConfig serves the OIDC discovery document.
func (h *Handler) WellKnownOpenIDConfig() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, err := h.tenantFromHost(r.Host)
		if err != nil {
			http.Error(w, "unknown tenant", http.StatusBadRequest)
			return
		}

		baseURL := tenant.Config.Issuer

		resp := map[string]any{
			"issuer":                 baseURL,
			"authorization_endpoint": baseURL + RouteOAuth2Authorize,
			"token_endpoint":         baseURL + RouteOAuth2Token,
			"userinfo_endpoint":      baseURL + RouteUserInfo,
			"jwks_uri":               baseURL + RouteWellKnownJWKS,
			"revocation_endpoint":    baseURL + RouteOAuth2Revoke,
			"introspection_endpoint": baseURL + RouteOAuth2Introspect,

			"response_types_supported": []string{"code"},
			"response_modes_supported": []string{"query", "fragment"},
			"subject_types_supported":  []string{"public"},

			"id_token_signing_alg_values_supported": []string{"RS256"},

			"scopes_supported": []string{
				"openid",
				"profile",
				"email",
				"offline_access",
				"admin",
				"system:admin",
			},

			"token_endpoint_auth_methods_supported": []string{
				"client_secret_post",
				"none",
			},

			"grant_types_supported": []string{
				"authorization_code",
				"refresh_token",
				"client_credentials",
			},

			"code_challenge_methods_supported": []string{"S256", "plain"},

			"claims_supported": []string{
				"sub",
				"email",
				"email_verified",
				"given_name",
				"family_name",
				"preferred_username",
			},

			"ui_locales_supported": []string{"en-US", "en"},

			"claims_parameter_supported":      false,
			"request_parameter_supported":     false,
			"request_uri_parameter_supported": false,
		}

		w.Header().Set("Content-Type", contentTypeJSON)
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// JWKS returns the JSON Web Key Set used to validate tokens.
func (h *Handler) JWKS() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, err := h.tenantFromHost(r.Host)
		if err != nil {
			http.Error(w, "unknown tenant", http.StatusBadRequest)
			return
		}

		jwks, err := h.auth.GetJWKS(tenant.ID)
		if err != nil {
			http.Error(w, "Failed to get JWKS: "+err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", contentTypeJSON)
		w.Header().Set("Cache-Control", "public, max-age=3600")
		_ = json.NewEncoder(w).Encode(jwks)
	}
}

// Authorize begins the authorization flow.
func (h *Handler) Authorize() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, err := h.tenantFromHost(r.Host)
		if err != nil {
			http.Error(w, "unknown tenant", http.StatusBadRequest)
			return
		}
		params, err := parseAuthorizationParameters(tenant.ID, r)
		if err != nil {
			http.Error(w, "Invalid authorization request: "+err.Error(), http.StatusBadRequest)
			return
		}

		loginRedirect := func(authSessionID string, ttl time.Duration, loginURL string) {
			h.setAuthSessionCookie(w, r, authSessionID, int(ttl.Seconds()))

			redirectURL := loginURL
			if email := r.URL.Query().Get("email"); email != "" {
				redirectURL += "?email=" + url.QueryEscape(email)
			}

			http.Redirect(w, r, redirectURL, http.StatusSeeOther)
		}

		oauthRedirect := func(redirectURI string, responseMode oauthmodel.ResponseModeType, authCode string, state string) {
			if err := h.callbackRedirect(w, r, redirectURI, responseMode, authCode, state); err != nil {
				http.Error(w, "Failed to redirect to client: "+err.Error(), http.StatusInternalServerError)
			}
		}

		if err := h.auth.Authorize(params, loginRedirect, oauthRedirect); err != nil {
			http.Error(w, "Authorization failed: "+err.Error(), http.StatusBadRequest)
			return
		}
	}
}

// Token exchanges code/credentials for tokens.
func (h *Handler) Token() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, err := h.tenantFromHost(r.Host)
		if err != nil {
			http.Error(w, "unknown tenant", http.StatusBadRequest)
			return
		}

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

		tokenResponse, err := h.auth.Token(tokenReq)
		if err != nil {
			writeJSONError(w, "invalid_grant", err.Error(), http.StatusBadRequest)
			return
		}

		w.Header().Set("Content-Type", contentTypeJSON)
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Pragma", "no-cache")
		_ = json.NewEncoder(w).Encode(tokenResponse)
	}
}

// Introspect introspects tokens.
func (h *Handler) Introspect() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, err := h.tenantFromHost(r.Host)
		if err != nil {
			http.Error(w, "unknown tenant", http.StatusBadRequest)
			return
		}

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

		introspection, err := h.auth.IntrospectToken(tenant.ID, token, clientID, clientSecret)
		if err != nil {
			writeJSONError(w, "server_error", err.Error(), http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", contentTypeJSON)
		_ = json.NewEncoder(w).Encode(introspection)
	}
}

// Revoke revokes tokens.
func (h *Handler) Revoke() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tenant, err := h.tenantFromHost(r.Host)
		if err != nil {
			http.Error(w, "unknown tenant", http.StatusBadRequest)
			return
		}
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

		if err := h.auth.RevokeToken(tenant.ID, token, tokenTypeHint, clientID, clientSecret); err != nil {
			writeJSONError(w, "invalid_client", err.Error(), http.StatusUnauthorized)
			return
		}

		w.WriteHeader(http.StatusNoContent)
	}
}

// UserInfo returns information about the user.
func (h *Handler) UserInfo() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

		userInfo, err := h.auth.UserInfo(parts[1])
		if err != nil {
			writeJSONError(w, "invalid_token", err.Error(), http.StatusUnauthorized)
			return
		}

		w.Header().Set("Content-Type", contentTypeJSON)
		_ = json.NewEncoder(w).Encode(userInfo)
	}
}

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

	if r.URL.Query().Get("response_mode") != "" {
		params.ResponseMode = oauthmodel.ResponseModeType(r.URL.Query().Get("response_mode"))
	}

	return params, nil
}

func writeJSONError(w http.ResponseWriter, errorCode, description string, statusCode int) {
	w.Header().Set("Content-Type", contentTypeJSON)
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             errorCode,
		"error_description": description,
	})
}

func (h *Handler) callbackRedirect(w http.ResponseWriter, r *http.Request, callbackURI string, responseMode oauthmodel.ResponseModeType, authCode string, state string) error {
	u, err := url.Parse(callbackURI)
	if err != nil {
		return fmt.Errorf("[callbackRedirect] invalid redirect URI: %w", err)
	}

	switch responseMode {
	case oauthmodel.FragmentResponseMode:
		params := url.Values{}
		params.Set("code", authCode)
		if state != "" {
			params.Set("state", state)
		}
		u.Fragment = params.Encode()
		http.Redirect(w, r, u.String(), http.StatusSeeOther)
	default:
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

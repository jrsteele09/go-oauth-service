package server

import (
	"encoding/json"
	"net/http"
)

// WellKnownOpenIDConfigHandler serves a minimal OIDC discovery document
func (s *Server) WellKnownOpenIDConfigHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		// Minimal stub; values should be updated based on deployment config
		issuer := r.URL.Scheme + "://" + r.Host
		if issuer == "://" { // scheme may not be set; fallback to https
			issuer = "https://" + r.Host
		}
		resp := map[string]any{
			"issuer":                                issuer,
			"authorization_endpoint":                "/oauth2/authorize",
			"token_endpoint":                        "/oauth2/token",
			"userinfo_endpoint":                     "/userinfo",
			"jwks_uri":                              "/.well-known/jwks.json",
			"revocation_endpoint":                   "/oauth2/revoke",
			"introspection_endpoint":                "/oauth2/introspect",
			"response_types_supported":              []string{"code", "token", "id_token", "code token", "code id_token"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials", "password"},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}
}

// JWKsHandler returns the JSON Web Key Set used to validate tokens (stub)
func (s *Server) JWKsHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		// TODO: populate with real public keys
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{}})
	}
}

// OAuth2AuthorizeHandler begins the authorization flow (stub)
func (s *Server) OAuth2AuthorizeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// TODO: validate client_id, redirect_uri, scope, state, response_type
		http.Error(w, "OAuth2 /authorize not yet implemented", http.StatusNotImplemented)
	}
}

// OAuth2TokenHandler exchanges code/credentials for tokens (stub)
func (s *Server) OAuth2TokenHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{"error": "not_implemented"})
	}
}

// OAuth2IntrospectHandler introspects tokens (stub)
func (s *Server) OAuth2IntrospectHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{"active": false})
	}
}

// OAuth2RevokeHandler revokes tokens (stub)
func (s *Server) OAuth2RevokeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// UserInfoHandler returns information about the user (stub)
func (s *Server) UserInfoHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": "stub", "email": "stub@example.com"})
	}
}

// OAuth2LogoutHandler logs a user out (stub)
func (s *Server) OAuth2LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "OAuth2 logout not yet implemented", http.StatusNotImplemented)
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

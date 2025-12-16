package server

import (
	"fmt"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jrsteele09/go-auth-server/server/loginsession"
	"golang.org/x/oauth2"
)

func (s *Server) OAuthCallbackHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Parse form to support both GET (query params) and POST (form_post response mode)
		// r.FormValue works for both query params and POST form data
		state := r.FormValue("state")
		code := r.FormValue("code")
		errorParam := r.FormValue("error")
		errorDesc := r.FormValue("error_description")

		// Check for authorization errors
		if errorParam != "" {
			http.Error(w, fmt.Sprintf("Authorization failed: %s - %s", errorParam, errorDesc), http.StatusBadRequest)
			return
		}

		if code == "" || state == "" {
			http.Error(w, "Missing code or state parameter", http.StatusBadRequest)
			return
		}

		authState, err := s.authState.Get(state)
		if err != nil || authState == nil {
			http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		}

		// Clean up state after use
		err = s.authState.Delete(state)
		if err != nil {
			http.Error(w, "Invalid state parameter", http.StatusInternalServerError)
			return
		}

		// Get tenant
		tenant, err := s.tenantFromHost(r.Host)
		if err != nil {
			http.Error(w, "Tenant not found", http.StatusNotFound)
			return
		}

		// Get OIDC configuration for tenant (same pattern as RequireSessionAuth)
		oidcConfig, err := s.getOidcConfigForTenant(r.Context(), tenant)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to get OIDC config: %v", err), http.StatusInternalServerError)
			return
		}

		// Exchange authorization code for tokens using standard oauth2 library
		oauth2Token, err := oidcConfig.OAuth2Config.Exchange(
			r.Context(),
			code,
			oauth2.SetAuthURLParam("code_verifier", authState.CodeVerifier),
		)
		if err != nil {
			http.Error(w, fmt.Sprintf("Token exchange failed: %v", err), http.StatusInternalServerError)
			return
		}

		// Extract ID token and verify it
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			http.Error(w, "No ID token in response", http.StatusInternalServerError)
			return
		}

		// Verify the ID token signature and claims (including nonce)
		idToken, err := oidcConfig.OidcProvider.Verifier(&oidc.Config{
			ClientID: oidcConfig.OAuth2Config.ClientID,
		}).Verify(r.Context(), rawIDToken)
		if err != nil {
			http.Error(w, fmt.Sprintf("ID token verification failed: %v", err), http.StatusInternalServerError)
			return
		}

		// Extract and validate claims in one pass
		var claims struct {
			Nonce string `json:"nonce"`
			Sub   string `json:"sub"`
			Email string `json:"email"`
			Name  string `json:"name"`
		}
		if err := idToken.Claims(&claims); err != nil {
			http.Error(w, fmt.Sprintf("Failed to extract claims: %v", err), http.StatusInternalServerError)
			return
		}

		// Validate nonce to prevent replay attacks
		if claims.Nonce != authState.Nonce {
			http.Error(w, "Invalid nonce", http.StatusUnauthorized)
			return
		}

		// Check if user requires password reset
		user, err := s.repos.Users.GetByEmail(tenant.ID, claims.Email)
		if err != nil {
			http.Error(w, fmt.Sprintf("Failed to get user: %v", err), http.StatusInternalServerError)
			return
		}

		// Create login session with tokens and user identity
		sessionID := generateRandomString(32)
		loginSession := loginsession.Session{
			TenantID:     tenant.ID,
			ClientID:     oidcConfig.OAuth2Config.ClientID,
			UserID:       claims.Sub,
			Email:        claims.Email,
			Name:         claims.Name,
			RefreshToken: oauth2Token.RefreshToken,
			AccessToken:  oauth2Token.AccessToken,
			Scopes:       oidcConfig.OAuth2Config.Scopes,
			ExpiresAt:    oauth2Token.Expiry,
			CreatedAt:    time.Now(),
		}

		if err := s.loginSessions.Upsert(tenant.ID, sessionID, loginSession); err != nil {
			http.Error(w, fmt.Sprintf("Failed to create session: %v", err), http.StatusInternalServerError)
			return
		}

		// Set session cookie with expiry from oauth2 token
		expiresIn := int(time.Until(oauth2Token.Expiry).Seconds())
		s.SetLoginSessionCookie(w, sessionID, r, expiresIn)

		// If user requires password change, redirect to password reset page
		if user.PasswordChangeRequired {
			passwordResetURL := RouteChangePassword + "?required=true"
			redirectSuccess(w, r, passwordResetURL)
			return
		}

		// Redirect to original destination or dashboard
		returnURL := authState.ReturnURL
		if returnURL == "" || returnURL == "/" {
			returnURL = RouteAdminDashboard
		}
		redirectSuccess(w, r, returnURL)
	}
}

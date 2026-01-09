package server

import (
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jrsteele09/go-auth-server/server/loginsession"
	"github.com/rs/zerolog/log"
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
			log.Error().Msgf("OAuth authorization error: %s - %s", errorParam, errorDesc)
			redirectPage(w, r, "/")
			return
		}

		if code == "" || state == "" {
			log.Error().Msg("Missing code or state parameter in OAuth callback")
			redirectPage(w, r, "/")
			return
		}

		authState, err := s.callbackState.Get(state)
		if err != nil || authState == nil {
			log.Error().Msg("Invalid state parameter in OAuth callback")
			redirectPage(w, r, "/")
			return
		}

		// Clean up state after use
		err = s.callbackState.Delete(state)
		if err != nil {
			log.Error().Msgf("Failed to delete auth state: %v", err)
			redirectPage(w, r, "/")
			return
		}

		// Get tenant
		tenant, err := s.tenantFromHost(r.Host)
		if err != nil {
			log.Error().Msgf("Tenant not found for host %s: %v", r.Host, err)
			redirectPage(w, r, "/")
			return
		}

		// Get OIDC configuration for tenant (same pattern as RequireSessionAuth)
		oidcConfig, err := s.getOidcConfigForTenant(r.Context(), tenant)
		if err != nil {
			log.Error().Msgf("Failed to get OIDC config for tenant %s: %v", tenant.ID, err)
			redirectPage(w, r, "/")
			return
		}

		// Exchange authorization code for tokens using standard oauth2 library
		oauth2Token, err := oidcConfig.OAuth2Config.Exchange(
			r.Context(),
			code,
			oauth2.SetAuthURLParam("code_verifier", authState.CodeVerifier),
		)
		if err != nil {
			log.Error().Msgf("Token exchange failed: %v", err)
			redirectPage(w, r, "/")
			return
		}

		// Extract ID token and verify it
		rawIDToken, ok := oauth2Token.Extra("id_token").(string)
		if !ok {
			log.Error().Msg("No ID token in response")
			redirectPage(w, r, "/")
			return
		}

		// Verify the ID token signature and claims (including nonce)
		idToken, err := oidcConfig.OidcProvider.Verifier(&oidc.Config{
			ClientID: oidcConfig.OAuth2Config.ClientID,
		}).Verify(r.Context(), rawIDToken)
		if err != nil {
			log.Error().Msgf("ID token verification failed: %v", err)
			redirectPage(w, r, "/")
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
			log.Error().Msgf("Failed to extract claims: %v", err)
			redirectPage(w, r, "/")
			return
		}

		// Validate nonce to prevent replay attacks
		if claims.Nonce != authState.Nonce {
			log.Error().Msg("Invalid nonce in ID token")
			redirectPage(w, r, "/")
			return
		}

		// Check if user requires password reset
		user, err := s.repos.Users.GetByEmail(tenant.ID, claims.Email)
		if err != nil {
			log.Error().Msgf("Failed to get user by email %s: %v", claims.Email, err)
			redirectPage(w, r, "/")
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
			ExpiresAt:    time.Now().Add(tenant.Config.GetRefreshTokenExpiry(s.config.GetDefaultRefreshTokenExpiry())),
			CreatedAt:    time.Now(),
		}

		if err := s.loginSessions.Upsert(tenant.ID, sessionID, loginSession); err != nil {
			log.Error().Msgf("Failed to create session: %v", err)
			redirectPage(w, r, "/")
			return
		}

		// Set session cookie with expiry based on tenant config
		refreshTokenExpiry := tenant.Config.GetRefreshTokenExpiry(s.config.GetDefaultRefreshTokenExpiry())
		expiresIn := int(refreshTokenExpiry.Seconds())
		s.SetLoginSessionCookie(w, r, sessionID, expiresIn)

		// If user requires password change, redirect to password reset page
		if user.PasswordChangeRequired {
			passwordResetURL := RouteChangePassword + "?required=true"
			redirectPage(w, r, passwordResetURL)
			return
		}

		// Redirect to original destination or dashboard
		returnURL := authState.ReturnURL
		if returnURL == "" || returnURL == "/" {
			returnURL = RouteAdminDashboard
		}
		redirectPage(w, r, returnURL)
	}
}

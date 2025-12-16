package server

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jrsteele09/go-auth-server/tenants"
	"golang.org/x/oauth2"
)

const (
	// loggedInSessionID is the name of the cookie used for admin UI session authentication
	loggedInSessionID = "loggedInSessionId"
	// authSessionCookieName is the name of the cookie used to track OAuth authorization sessions
	authSessionCookieName = "auth_session_id"
)

// generateRandomString creates a random base64url string
func generateRandomString(length int) string {
	b := make([]byte, length)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// generateCodeChallenge creates a PKCE code challenge from a verifier
func generateCodeChallenge(verifier string) string {
	hash := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}

func (s *Server) SetLoginSessionCookie(w http.ResponseWriter, sessionID string, r *http.Request, maxAge int) {
	isSecure := getScheme(r) == "https"

	http.SetCookie(w, &http.Cookie{
		Name:     loggedInSessionID,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

func (s *Server) SetAuthSessionCookie(w http.ResponseWriter, authSessionID string, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     authSessionCookieName,
		Value:    authSessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil, // Only set Secure flag if using HTTPS
		SameSite: http.SameSiteLaxMode,
		MaxAge:   60, // 60 seconds - just long enough for redirect and page load
	})
}

func (s *Server) getOidcConfigForTenant(ctx context.Context, tenant *tenants.Tenant) (OidcConfig, error) {
	s.tenantOidcLock.RLock()
	config, exists := s.tenantOidc[tenant.ID]
	s.tenantOidcLock.RUnlock()
	if exists {
		return config, nil
	}

	issuerURL := tenant.Config.Issuer // e.g., "https://tenant-a.example.com"

	// Get the client Info
	client, err := s.repos.Clients.Get(tenant.ID, s.config.GetAdminClientID())
	if err != nil {
		return OidcConfig{}, fmt.Errorf("failed to get client: %w", err)
	}

	provider, err := oidc.NewProvider(ctx, tenant.Config.Issuer)
	if err != nil {
		return OidcConfig{}, fmt.Errorf("failed to create OIDC provider: %w", err)
	}

	oidcConfig := OidcConfig{
		OidcProvider: provider,
		OAuth2Config: &oauth2.Config{
			ClientID:     s.config.GetAdminClientID(),
			ClientSecret: client.Secret,
			Endpoint:     provider.Endpoint(),
			RedirectURL:  issuerURL + RouteCallback, // Same base URL
			Scopes:       []string{oidc.ScopeOpenID, "profile", "email", oidc.ScopeOfflineAccess},
		},
		OidcVerifier: provider.Verifier(&oidc.Config{
			ClientID: s.config.GetAdminClientID(),
		}),
	}
	s.tenantOidcLock.Lock()
	s.tenantOidc[tenant.ID] = oidcConfig
	s.tenantOidcLock.Unlock()

	return oidcConfig, nil
}

func (s *Server) tenantFromHost(host string) (*tenants.Tenant, error) {
	splitHost := strings.SplitN(host, ":", 2)
	host = splitHost[0]

	domainURL := s.config.GetBaseURL()
	splitDomain := strings.SplitN(domainURL, "://", 2)

	baseDomainName := splitDomain[0]
	if len(splitDomain) > 0 {
		baseDomainName = splitDomain[1]
	}

	splitBaseDomain := strings.SplitN(baseDomainName, ":", 2)
	baseHostName := splitBaseDomain[0]

	tenantID := strings.Replace(host, baseHostName, "", 1)
	tenantID = strings.Trim(tenantID, ".")

	if tenantID == "" {
		tenantID = s.config.GetSystemTenantID()
	}

	t, err := s.repos.Tenants.Get(tenantID) // verify tenant exists
	if err != nil {
		return nil, fmt.Errorf("[server tenantHost] unknown tenant: %w", err)
	}

	return t, nil
}

// redirectSuccess helper for htmx-aware success redirects
func redirectSuccess(w http.ResponseWriter, r *http.Request, path string) {
	if isHTMXRequest(r) {
		w.Header().Set("HX-Redirect", path)
		w.WriteHeader(http.StatusNoContent) // 204 - no content, just redirect instruction
		return
	}
	http.Redirect(w, r, path, http.StatusSeeOther)
}

// redirectWithError helper for htmx-aware error redirects
func redirectWithError(w http.ResponseWriter, r *http.Request, path, errorMsg string) {
	fullPath := path + "?error=" + url.QueryEscape(errorMsg)

	if isHTMXRequest(r) {
		w.Header().Set("HX-Redirect", fullPath)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, fullPath, http.StatusSeeOther)
}

// isHTMXRequest checks if the request was initiated by HTMX
func isHTMXRequest(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true"
}

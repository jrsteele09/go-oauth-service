package ui

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jrsteele09/go-auth-server/auth/oauthmodel"
	"github.com/jrsteele09/go-auth-server/auth/users"
	"github.com/jrsteele09/go-auth-server/server/ui/adminsession"
	"github.com/jrsteele09/go-auth-server/utils"
	"github.com/rs/zerolog/log"
)

// LoginPageData contains data for rendering the login page
type LoginPageData struct {
	TenantID      string
	TenantName    string
	FormAction    string
	AuthSessionID string
	Error         string
	Email         string // Preserve email on error
}

// AuthLoginPageHandler displays the OAuth login page used by /oauth2/authorize.
func (h *UIHandler) AuthLoginPageHandler() http.HandlerFunc {
	loginTmpl, err := ParseTemplate("login.html")
	if err != nil {
		log.Err(err).Msg("Failed to parse OAuth login template")
	}

	return func(w http.ResponseWriter, r *http.Request) {
		tenant, err := h.tenantFromHost(r.Host)
		if err != nil {
			http.Error(w, "Tenant not found", http.StatusBadRequest)
			return
		}

		authSessionID := r.URL.Query().Get("session_id")
		if authSessionID == "" {
			authSessionID = r.URL.Query().Get("auth_session_id")
		}
		if authSessionID == "" {
			if cookie, err := r.Cookie(authSessionCookieName); err == nil {
				authSessionID = cookie.Value
			}
		}
		if authSessionID == "" {
			http.Error(w, "Missing authorization session", http.StatusBadRequest)
			return
		}

		data := LoginPageData{
			TenantID:      tenant.ID,
			TenantName:    tenant.Name,
			FormAction:    RouteAuthLogin,
			AuthSessionID: authSessionID,
			Error:         r.URL.Query().Get("error"),
			Email:         r.URL.Query().Get("email"),
		}

		w.Header().Set("Content-Type", contentTypeHTML)
		if err := loginTmpl.Execute(w, data); err != nil {
			log.Err(err).Msg("Failed to render OAuth login template")
			http.Error(w, "Failed to render login page", http.StatusInternalServerError)
		}
	}
}

func (h *UIHandler) AuthLoginSubmissionHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}

		authSessionID := r.FormValue(authSessionCookieName)
		if authSessionID == "" {
			if cookie, err := r.Cookie(authSessionCookieName); err == nil {
				authSessionID = cookie.Value
			}
		}
		email := strings.TrimSpace(r.FormValue("email"))
		password := r.FormValue("password")
		if authSessionID == "" || email == "" || password == "" {
			redirectOAuthLoginError(w, r, authSessionID, "Email and password are required", email)
			return
		}

		oauthRedirect := func(redirectURI string, responseMode oauthmodel.ResponseModeType, authCode string, state string) {
			if err := oauthCallbackRedirect(w, r, redirectURI, responseMode, authCode, state); err != nil {
				http.Error(w, "Failed to redirect to client: "+err.Error(), http.StatusInternalServerError)
			}
		}

		mfaRedirect := func(_ string, _ users.MFAuthType, _ string) {
			http.Error(w, "MFA is not implemented", http.StatusNotImplemented)
		}

		if err := h.auth.Login(authSessionID, email, password, oauthRedirect, mfaRedirect); err != nil {
			redirectOAuthLoginError(w, r, authSessionID, "Invalid email or password", email)
			return
		}
	}
}

// LoginPageUIHandler displays the admin login page.
func (h *UIHandler) LoginPageUIHandler() http.HandlerFunc {
	// Parse login template
	loginTmpl, err := ParseTemplate("login.html")
	if err != nil {
		log.Err(err).Msg("Failed to parse login template")
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := h.currentAdminSession(r); err == nil {
			utils.RedirectPage(w, r, RouteAdminDashboard)
			return
		}

		// Get tenant from host
		tenant, err := h.tenantFromHost(r.Host)
		if err != nil {
			http.Error(w, "Tenant not found", http.StatusBadRequest)
			return
		}

		// Get optional email and error parameters
		email := r.URL.Query().Get("email")
		errorMsg := r.URL.Query().Get("error")

		// Parse login template
		data := LoginPageData{
			TenantID:   tenant.ID,
			TenantName: tenant.Name,
			FormAction: RouteAdminLoginSubmit,
			Error:      errorMsg,
			Email:      email,
		}

		w.Header().Set("Content-Type", contentTypeHTML)
		if err := loginTmpl.Execute(w, data); err != nil {
			log.Err(err).Msg("Failed to render login template")
			http.Error(w, "Failed to render login page", http.StatusInternalServerError)
		}
	}
}

// LoginSubmissionHandler processes the login form submission
func (h *UIHandler) LoginSubmissionHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form data", http.StatusBadRequest)
			return
		}

		tenant, err := h.tenantFromHost(r.Host)
		if err != nil {
			http.Error(w, "Tenant not found", http.StatusBadRequest)
			return
		}

		email := strings.TrimSpace(r.FormValue("email"))
		password := r.FormValue("password")
		if email == "" || password == "" {
			utils.RedirectWithError(w, r, RouteAdminLogin, "Email and password are required")
			return
		}

		loginTenantID, user, err := h.adminUserForLogin(tenant.ID, email)
		if err != nil || user == nil || user.Blocked || !user.Verified || !users.CheckPasswordHash(password, user.PasswordHash) {
			utils.RedirectWithError(w, r, RouteAdminLogin, "Invalid email or password")
			return
		}
		if !user.IsSuperAdmin() && !user.HasTenantRole(loginTenantID, users.RoleTenantAdmin) {
			utils.RedirectWithError(w, r, RouteAdminLogin, "Admin access is required")
			return
		}

		sessionID, err := generateSessionID()
		if err != nil {
			http.Error(w, "Failed to create session", http.StatusInternalServerError)
			return
		}

		sessionExpiry := time.Now().Add(12 * time.Hour)
		session := adminsession.Session{
			TenantID:               loginTenantID,
			UserID:                 user.ID,
			Email:                  user.Email,
			PasswordChangeRequired: user.PasswordChangeRequired,
			CreatedAt:              time.Now(),
			ExpiresAt:              sessionExpiry,
		}
		if err := h.adminSessions.Upsert(sessionID, session); err != nil {
			http.Error(w, "Failed to create session", http.StatusInternalServerError)
			return
		}

		h.SetAdminSessionCookie(w, r, sessionID, int(time.Until(sessionExpiry).Seconds()))
		if user.PasswordChangeRequired {
			utils.RedirectPage(w, r, RouteChangePassword+"?required=true")
			return
		}
		utils.RedirectPage(w, r, RouteAdminDashboard)
	}
}

func (h *UIHandler) LogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie(adminSessionCookieName); err == nil {
			if err := h.adminSessions.Delete(cookie.Value); err != nil {
				log.Err(err).Msg("failed to delete admin session")
			}
		}
		h.SetAdminSessionCookie(w, r, "", -1)
		utils.RedirectPage(w, r, RouteAdminLogin)
	}
}

func (h *UIHandler) SetAdminSessionCookie(w http.ResponseWriter, r *http.Request, sessionID string, maxAge int) {
	isSecure := utils.GetScheme(r) == "https"

	http.SetCookie(w, &http.Cookie{
		Name:     adminSessionCookieName,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

func (h *UIHandler) currentAdminSession(r *http.Request) (adminsession.Session, error) {
	cookie, err := r.Cookie(adminSessionCookieName)
	if err != nil || cookie.Value == "" {
		return adminsession.Session{}, http.ErrNoCookie
	}
	return h.adminSessions.Get(cookie.Value)
}

func (h *UIHandler) adminUserForLogin(tenantID, email string) (string, *users.User, error) {
	user, err := h.users.GetByEmail(tenantID, email)
	if err == nil && user != nil {
		return tenantID, user, nil
	}

	systemTenantID := h.config.GetSystemTenantID()
	if strings.EqualFold(tenantID, systemTenantID) {
		return "", nil, err
	}

	user, err = h.users.GetByEmail(systemTenantID, email)
	if err != nil {
		return "", nil, err
	}
	if user != nil && user.IsSuperAdmin() {
		return systemTenantID, user, nil
	}
	return "", nil, err
}

func generateSessionID() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func redirectOAuthLoginError(w http.ResponseWriter, r *http.Request, authSessionID, errorMsg, email string) {
	q := url.Values{}
	if authSessionID != "" {
		q.Set("session_id", authSessionID)
	}
	if email != "" {
		q.Set("email", email)
	}
	q.Set("error", errorMsg)
	utils.RedirectPage(w, r, RouteAuthLogin+"?"+q.Encode())
}

func oauthCallbackRedirect(w http.ResponseWriter, r *http.Request, callbackURI string, responseMode oauthmodel.ResponseModeType, authCode string, state string) error {
	u, err := url.Parse(callbackURI)
	if err != nil {
		return fmt.Errorf("[oauthCallbackRedirect] invalid redirect URI: %w", err)
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

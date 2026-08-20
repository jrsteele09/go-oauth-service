package ui

import (
	"fmt"
	"net/http"

	"github.com/jrsteele09/go-auth-server/auth"
	"github.com/jrsteele09/go-auth-server/auth/clients"
	"github.com/jrsteele09/go-auth-server/auth/token/refresh"
	"github.com/jrsteele09/go-auth-server/auth/users"
	"github.com/jrsteele09/go-auth-server/config"
	"github.com/jrsteele09/go-auth-server/server/ui/adminsession"
	"github.com/jrsteele09/go-auth-server/tenants"
	"github.com/jrsteele09/go-auth-server/utils"
	"github.com/rs/zerolog/log"
)

const (
	authSessionCookieName  = "auth_session_id"
	adminSessionCookieName = "admin_session_id"
	contentTypeHTML        = "text/html; charset=utf-8"

	// Auth Routes - Login & Logout
	RouteAuthLogin = "/auth/login"
	RouteCallback  = "/callback"

	// Auth Routes - Password Management
	RouteChangePassword = "/auth/change-password"

	// API Routes
	RouteAPIValidatePassword = "/api/validate-password"

	// Admin Routes
	RouteAdminLogin            = "/admin/login"
	RouteAdminLoginSubmit      = "/admin/auth/login"
	RouteAdminLogout           = "/admin/auth/logout"
	RouteAdminDashboard        = "/admin/dashboard"
	RouteAdminTenants          = "/admin/tenants"
	RouteAdminTenantNew        = "/admin/tenants/new"
	RouteAdminTenantEdit       = "/admin/tenants/edit"
	RouteAdminTenantSave       = "/admin/tenants/save"
	RouteAdminTenantDelete     = "/admin/tenants/delete"
	RouteAdminClients          = "/admin/clients"
	RouteAdminClientNew        = "/admin/clients/new"
	RouteAdminClientEdit       = "/admin/clients/edit"
	RouteAdminClientSave       = "/admin/clients/save"
	RouteAdminClientValidateID = "/admin/clients/validate-id"
	RouteAdminClientDelete     = "/admin/clients/delete"
	RouteAdminUsers            = "/admin/users"
	RouteAdminSettings         = "/admin/settings"
	RouteAdminProfile          = "/admin/profile"
)

type ContextKey string

const (
	// ContextKeyUserID stores the authenticated user ID
	ContextKeyUserID ContextKey = "user_id"
	// ContextKeyTenantID stores the tenant ID
	ContextKeyTenantID ContextKey = "tenant_id"
	// ContextKeyClientID stores the authenticated client ID
	ContextKeyClientID ContextKey = "client_id"
	// ContextKeyClaims stores parsed token claims
	ContextKeyClaims ContextKey = "claims"
	// ContextKeyScopes stores the token scopes
	ContextKeyScopes ContextKey = "scopes"
	// ContextKeySession stores the session information
	ContextKeySession ContextKey = "session"
)

type UIHandler struct {
	config        config.Config
	auth          *auth.AuthorizationService
	adminSessions adminsession.Repo
	tenants       tenants.Repo
	users         users.UserRepo
	refreshTokens refresh.Repo
	clients       clients.Repo
}

func NewUIHandler(config config.Config,
	authService *auth.AuthorizationService,
	adminSessions adminsession.Repo,
	tenants tenants.Repo,
	users users.UserRepo,
	refreshRepo refresh.Repo,
	clients clients.Repo) *UIHandler {

	return &UIHandler{
		config:        config,
		auth:          authService,
		adminSessions: adminSessions,
		tenants:       tenants,
		users:         users,
		refreshTokens: refreshRepo,
		clients:       clients,
	}
}

func (h UIHandler) InitRoutes(register func(pattern string, handler http.Handler)) {
	register("GET /", http.HandlerFunc(h.IndexHandler()))

	register("POST "+RouteAPIValidatePassword, http.HandlerFunc(h.ValidatePasswordHandler()))

	// OAuth browser login flow
	register("GET "+RouteAuthLogin, http.HandlerFunc(h.AuthLoginPageHandler()))
	register("POST "+RouteAuthLogin, http.HandlerFunc(h.AuthLoginSubmissionHandler()))

	// Admin UI login flow
	register("GET "+RouteAdminLogin, http.HandlerFunc(h.LoginPageUIHandler()))
	register("POST "+RouteAdminLoginSubmit, http.HandlerFunc(h.LoginSubmissionHandler()))
	register("GET "+RouteAdminLogout, http.HandlerFunc(h.LogoutHandler()))

	register("GET "+RouteChangePassword, http.HandlerFunc(utils.ChainMiddleware(h.ChangePasswordGetHandler(), h.HTMLMiddleWare(h.RequireSessionAuth(false))...)))
	register("POST "+RouteChangePassword, http.HandlerFunc(utils.ChainMiddleware(h.ChangePasswordPostHandler(), h.HTMLMiddleWare(h.RequireSessionAuth(false))...)))

	register("GET "+RouteAdminDashboard, http.HandlerFunc(utils.ChainMiddleware(h.AdminDashboardHandler(), h.HTMLMiddleWare(h.RequireSessionAuth(true))...)))
	register("GET "+RouteAdminTenants, http.HandlerFunc(utils.ChainMiddleware(h.AdminTenantsListHandler(), h.HTMLMiddleWare(h.RequireSessionAuth(true))...)))
	register("GET "+RouteAdminTenantNew, http.HandlerFunc(utils.ChainMiddleware(h.AdminTenantNewHandler(), h.HTMLMiddleWare(h.RequireSessionAuth(true))...)))
	register("GET "+RouteAdminTenantEdit, http.HandlerFunc(utils.ChainMiddleware(h.AdminTenantEditHandler(), h.HTMLMiddleWare(h.RequireSessionAuth(true))...)))
	register("POST "+RouteAdminTenantSave, http.HandlerFunc(utils.ChainMiddleware(h.AdminTenantSaveHandler(), h.HTMLMiddleWare(h.RequireSessionAuth(true))...)))
	register("DELETE "+RouteAdminTenantDelete, http.HandlerFunc(utils.ChainMiddleware(h.AdminTenantDeleteHandler(), h.HTMLMiddleWare(h.RequireSessionAuth(true))...)))

	register("GET "+RouteAdminClients, http.HandlerFunc(utils.ChainMiddleware(h.AdminClientsListHandler(), h.HTMLMiddleWare(h.RequireSessionAuth(true))...)))
	register("GET "+RouteAdminClientNew, http.HandlerFunc(utils.ChainMiddleware(h.AdminClientNewHandler(), h.HTMLMiddleWare(h.RequireSessionAuth(true))...)))
	register("GET "+RouteAdminClientEdit, http.HandlerFunc(utils.ChainMiddleware(h.AdminClientEditHandler(), h.HTMLMiddleWare(h.RequireSessionAuth(true))...)))
	register("POST "+RouteAdminClientSave, http.HandlerFunc(utils.ChainMiddleware(h.AdminClientSaveHandler(), h.HTMLMiddleWare(h.RequireSessionAuth(true))...)))
	register("POST "+RouteAdminClientValidateID, http.HandlerFunc(utils.ChainMiddleware(h.AdminClientValidateIDHandler(), h.HTMLMiddleWare(h.RequireSessionAuth(true))...)))
	register("DELETE "+RouteAdminClientDelete, http.HandlerFunc(utils.ChainMiddleware(h.AdminClientDeleteHandler(), h.HTMLMiddleWare(h.RequireSessionAuth(true))...)))

	register("GET "+RouteAdminUsers, http.HandlerFunc(utils.ChainMiddleware(h.AdminUsersListHandler(), h.HTMLMiddleWare(h.RequireSessionAuth(true))...)))
	register("GET "+RouteAdminSettings, http.HandlerFunc(utils.ChainMiddleware(h.AdminSettingsHandler(), h.HTMLMiddleWare(h.RequireSessionAuth(true))...)))
	register("GET "+RouteAdminProfile, http.HandlerFunc(utils.ChainMiddleware(h.AdminProfileHandler(), h.HTMLMiddleWare(h.RequireSessionAuth(true))...)))

	register("GET /css/fonts/{file}", http.HandlerFunc(utils.ChainMiddleware(ServeFileHandler(), h.HTMLMiddleWare()...)))
	register("GET /css/{file}", http.HandlerFunc(utils.ChainMiddleware(ServeFileHandler(), h.HTMLMiddleWare()...)))
	register("GET /js/{file}", http.HandlerFunc(utils.ChainMiddleware(ServeFileHandler(), h.HTMLMiddleWare()...)))
	register("GET /{file}", http.HandlerFunc(utils.ChainMiddleware(ServeFileHandler(), h.HTMLMiddleWare()...)))
}

func logError(method, path, error string) {
	var displayMethod string
	paddedMethod := fmt.Sprintf(" %-7s", method)
	if color, ok := utils.MethodColors[method]; ok {
		displayMethod = color + paddedMethod + utils.ResetColor
	} else {
		displayMethod = utils.Gray + paddedMethod + utils.ResetColor
	}
	errorString := utils.Red + error + utils.ResetColor
	log.Printf("[%-19s] %s %s\n", displayMethod, path, errorString)
}

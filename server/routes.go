package server

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/jrsteele09/go-auth-server/server/ui"
)

func (s *Server) initRoutes() {
	s.RegisterRouteFunc("GET /", s.IndexHandler())

	// LOGIN
	s.RegisterRouteFunc("GET "+RouteLogin, s.LoginPageUIHandler())
	s.RegisterRouteFunc("POST "+RouteAuthLogin, s.LoginSubmissionHandler())
	s.RegisterRouteFunc("GET "+RouteAuthLogout, s.LogoutHandler())
	s.RegisterRouteFunc("GET "+RouteCallback, s.OAuthCallbackHandler())
	s.RegisterRouteFunc("POST "+RouteCallback, s.OAuthCallbackHandler()) // For form_post response mode

	// TODO
	s.RegisterRouteFunc("GET "+RouteVerifyEmail, s.VerifyEmailHandler())
	s.RegisterRouteFunc("POST "+RouteResendVerification, s.ResendVerificationHandler())

	// TODO
	s.RegisterRouteFunc("GET "+RouteConsent, s.ConsentGetHandler())
	s.RegisterRouteFunc("POST "+RouteConsent, s.ConsentPostHandler())

	// TODO:
	s.RegisterRouteFunc("GET "+RouteSignup, s.SignupGetHandler())
	s.RegisterRouteFunc("POST "+RouteSignup, s.SignupPostHandler())

	// TODO: Merge password change/reset handlers
	s.RegisterRouteFunc("GET "+RouteChangePassword, s.ChangePasswordGetHandler())
	s.RegisterRouteFunc("POST "+RouteChangePassword, s.ChangePasswordPostHandler())

	s.RegisterRouteFunc("GET "+RouteForgotPassword, s.ForgotPasswordGetHandler())
	s.RegisterRouteFunc("POST "+RouteForgotPassword, s.ForgotPasswordPostHandler())

	s.RegisterRouteFunc("GET "+RouteResetPassword, s.ResetPasswordGetHandler())
	s.RegisterRouteFunc("POST "+RouteResetPassword, s.ResetPasswordPostHandler())

	// API routes
	s.RegisterRouteFunc("POST "+RouteAPIValidatePassword, s.ValidatePasswordHandler())

	// Admin routes (require session-based auth for HTML/HTMX UI)
	s.RegisterRouteHandler("GET "+RouteAdminDashboard, ChainMiddleware(s.AdminDashboardHandler(), s.HTMLMiddleWare(s.RequireSessionAuth())...))
	s.RegisterRouteHandler("GET "+RouteAdminTenants, ChainMiddleware(s.AdminTenantsListHandler(), s.HTMLMiddleWare(s.RequireSessionAuth())...))
	s.RegisterRouteHandler("GET "+RouteAdminClients, ChainMiddleware(s.AdminClientsListHandler(), s.HTMLMiddleWare(s.RequireSessionAuth())...))
	s.RegisterRouteHandler("GET "+RouteAdminUsers, ChainMiddleware(s.AdminUsersListHandler(), s.HTMLMiddleWare(s.RequireSessionAuth())...))
	s.RegisterRouteHandler("GET "+RouteAdminSettings, ChainMiddleware(s.AdminSettingsHandler(), s.HTMLMiddleWare(s.RequireSessionAuth())...))
	s.RegisterRouteHandler("GET "+RouteAdminProfile, ChainMiddleware(s.AdminProfileHandler(), s.HTMLMiddleWare(s.RequireSessionAuth())...))

	// OAuth2 / OIDC API routes
	s.RegisterRouteHandler("GET "+RouteWellKnownOpenIDConfig, ChainMiddleware(s.WellKnownOpenIDConfig(), s.APIMiddleware()...))
	s.RegisterRouteHandler("GET "+RouteWellKnownJWKS, ChainMiddleware(s.JWKS(), s.APIMiddleware()...))
	s.RegisterRouteHandler("GET "+RouteOAuth2Authorize, ChainMiddleware(s.Authorize(), s.APIMiddleware()...))
	s.RegisterRouteHandler("POST "+RouteOAuth2Token, ChainMiddleware(s.Token(), s.APIMiddleware()...))

	// Protected OAuth2 endpoints (require valid access token or client credentials)
	s.RegisterRouteHandler("GET "+RouteUserInfo, ChainMiddleware(s.UserInfo(), s.APIMiddleware()...))
	s.RegisterRouteHandler("POST "+RouteOAuth2Introspect, ChainMiddleware(s.Introspect(), s.APIMiddleware()...))
	s.RegisterRouteHandler("POST "+RouteOAuth2Revoke, ChainMiddleware(s.Revoke(), s.APIMiddleware()...))

	s.RegisterRouteHandler("GET "+RouteStaticCSSFonts, ChainMiddleware(s.serveFileHandler(), s.HTMLMiddleWare()...))
	s.RegisterRouteHandler("GET "+RouteStaticCSS, ChainMiddleware(s.serveFileHandler(), s.HTMLMiddleWare()...))
	s.RegisterRouteHandler("GET "+RouteStaticJS, ChainMiddleware(s.serveFileHandler(), s.HTMLMiddleWare()...))
	s.RegisterRouteHandler("GET /{file}", ChainMiddleware(s.serveFileHandler(), s.HTMLMiddleWare()...))
}

func (s *Server) serveFileHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		filePath := strings.TrimPrefix(r.URL.Path, "/")
		if filePath == "" {
			http.Error(w, "404 - Page Not Found", http.StatusNotFound)
			return
		}
		err := StreamFile(w, r, filePath)
		if err != nil {
			logError("GET", filePath, err.Error())
			http.Error(w, "404 - Page Not Found", http.StatusNotFound)
			return
		}
	}
}

func logError(method, path, error string) {
	var displayMethod string
	paddedMethod := fmt.Sprintf(" %-7s", method)
	if color, ok := ui.MethodColors[method]; ok {
		displayMethod = color + paddedMethod + ui.ResetColor
	} else {
		displayMethod = ui.Gray + paddedMethod + ui.ResetColor
	}
	errorString := ui.Red + error + ui.ResetColor
	log.Printf("[%-19s] %s %s\n", displayMethod, path, errorString)
}

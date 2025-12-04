package server

import (
	"fmt"
	"log"
	"net/http"
	"strings"
)

func (s *Server) initRoutes() {
	// UI routes
	s.RegisterRouteFunc("GET /", s.IndexHandler())
	s.RegisterRouteFunc("GET /auth/login", s.LoginPageHandler())
	s.RegisterRouteFunc("POST /auth/login", s.LoginHandler())
	s.RegisterRouteFunc("GET /auth/logout", s.LogoutHandler())
	s.RegisterRouteFunc("GET /auth/forgot-password", s.ForgotPasswordGetHandler())
	s.RegisterRouteFunc("POST /auth/forgot-password", s.ForgotPasswordPostHandler())
	s.RegisterRouteFunc("GET /auth/reset-password", s.ResetPasswordGetHandler())
	s.RegisterRouteFunc("POST /auth/reset-password", s.ResetPasswordPostHandler())
	s.RegisterRouteFunc("GET /auth/verify-email", s.VerifyEmailHandler())
	s.RegisterRouteFunc("POST /auth/verify-email/resend", s.ResendVerificationHandler())
	s.RegisterRouteFunc("GET /auth/consent", s.ConsentGetHandler())
	s.RegisterRouteFunc("POST /auth/consent", s.ConsentPostHandler())
	s.RegisterRouteFunc("GET /auth/signup", s.SignupGetHandler())
	s.RegisterRouteFunc("POST /auth/signup", s.SignupPostHandler())
	s.RegisterRouteFunc("GET /auth/change-password", s.ChangePasswordGetHandler())
	s.RegisterRouteFunc("POST /auth/change-password", s.ChangePasswordPostHandler())

	// API routes
	s.RegisterRouteFunc("POST /api/validate-password", s.ValidatePasswordHandler())

	// Admin routes (require session-based auth for HTML/HTMX UI)
	s.RegisterRouteHandler("GET /admin/dashboard", ChainMiddleware(s.AdminDashboardHandler(), append(s.StdMiddleware(), s.RequireSessionAuth(), s.RequireSuperAdmin())...))
	s.RegisterRouteHandler("GET /admin/tenants", ChainMiddleware(s.AdminTenantsListHandler(), append(s.StdMiddleware(), s.RequireSessionAuth(), s.RequireSuperAdmin())...))
	s.RegisterRouteHandler("GET /admin/users", ChainMiddleware(s.AdminUsersListHandler(), append(s.StdMiddleware(), s.RequireSessionAuth(), s.RequireSuperAdmin())...))

	// OAuth2 / OIDC API routes (stubs)
	// Public discovery/flow endpoints (apply standard middleware)
	s.RegisterRouteHandler("GET /.well-known/openid-configuration", ChainMiddleware(s.WellKnownOpenIDConfigHandler(), s.StdMiddleware()...))
	s.RegisterRouteHandler("GET /.well-known/jwks.json", ChainMiddleware(s.JWKsHandler(), s.StdMiddleware()...))
	s.RegisterRouteHandler("GET /oauth2/authorize", ChainMiddleware(s.OAuth2AuthorizeHandler(), s.StdMiddleware()...))
	s.RegisterRouteHandler("POST /oauth2/token", ChainMiddleware(s.OAuth2TokenHandler(), s.StdMiddleware()...))
	s.RegisterRouteHandler("POST /oauth2/device/code", ChainMiddleware(s.OAuth2DeviceCodeHandler(), s.StdMiddleware()...))
	s.RegisterRouteHandler("POST /oauth2/par", ChainMiddleware(s.OAuth2PARHandler(), s.StdMiddleware()...))

	// Protected OAuth2 endpoints (require valid access token or client credentials)
	s.RegisterRouteHandler("GET /userinfo", ChainMiddleware(s.UserInfoHandler(), append(s.StdMiddleware(), s.RequireAuth())...))
	s.RegisterRouteHandler("POST /oauth2/introspect", ChainMiddleware(s.OAuth2IntrospectHandler(), append(s.StdMiddleware(), s.RequireClientAuth())...))
	s.RegisterRouteHandler("POST /oauth2/revoke", ChainMiddleware(s.OAuth2RevokeHandler(), append(s.StdMiddleware(), s.RequireClientAuth())...))
	s.RegisterRouteHandler("GET /oauth2/logout", ChainMiddleware(s.OAuth2LogoutHandler(), append(s.StdMiddleware(), s.RequireAuth())...))

	// Static file folders
	s.RegisterRouteHandler("GET /css/fonts/{file}", ChainMiddleware(s.serveFileHandler(), s.StdMiddleware()...))
	s.RegisterRouteHandler("GET /css/{file}", ChainMiddleware(s.serveFileHandler(), s.StdMiddleware()...))
	s.RegisterRouteHandler("GET /js/{file}", ChainMiddleware(s.serveFileHandler(), s.StdMiddleware()...))
	s.RegisterRouteHandler("GET /{file}", ChainMiddleware(s.serveFileHandler(), s.StdMiddleware()...))
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
	if color, ok := methodColors[method]; ok {
		displayMethod = color + paddedMethod + ResetColor
	} else {
		displayMethod = Gray + paddedMethod + ResetColor
	}
	errorString := Red + error + ResetColor
	log.Printf("[%-19s] %s %s\n", displayMethod, path, errorString)
}

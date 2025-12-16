package server

// Route path constants
// All application routes are defined here to ensure consistency and prevent typos
const (
	// Auth Routes - Login & Logout
	RouteLogin      = "/login"
	RouteAuthLogin  = "/auth/login"
	RouteAuthLogout = "/auth/logout"
	RouteCallback   = "/callback"

	// Auth Routes - Password Management
	RouteChangePassword = "/auth/change-password"
	RouteForgotPassword = "/auth/forgot-password"
	RouteResetPassword  = "/auth/reset-password"

	// Auth Routes - Email Verification
	RouteVerifyEmail        = "/auth/verify-email"
	RouteResendVerification = "/auth/verify-email/resend"

	// Auth Routes - User Consent
	RouteConsent = "/auth/consent"

	// Auth Routes - Signup
	RouteSignup = "/auth/signup"

	// API Routes
	RouteAPIValidatePassword = "/api/validate-password"

	// Admin Routes
	RouteAdminDashboard = "/admin/dashboard"
	RouteAdminTenants   = "/admin/tenants"
	RouteAdminClients   = "/admin/clients"
	RouteAdminUsers     = "/admin/users"
	RouteAdminSettings  = "/admin/settings"
	RouteAdminProfile   = "/admin/profile"

	// OAuth2 / OIDC Routes
	RouteWellKnownOpenIDConfig = "/.well-known/openid-configuration"
	RouteWellKnownJWKS         = "/.well-known/jwks.json"
	RouteOAuth2Authorize       = "/oauth2/authorize"
	RouteOAuth2Token           = "/oauth2/token"
	RouteOAuth2Introspect      = "/oauth2/introspect"
	RouteOAuth2Revoke          = "/oauth2/revoke"
	RouteOAuth2Logout          = "/oauth2/logout"
	RouteUserInfo              = "/userinfo"

	// Static Asset Routes (patterns)
	RouteStaticCSS      = "/css/{file}"
	RouteStaticCSSFonts = "/css/fonts/{file}"
	RouteStaticJS       = "/js/{file}"
)

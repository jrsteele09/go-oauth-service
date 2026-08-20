package server

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/jrsteele09/go-auth-server/auth"
	"github.com/jrsteele09/go-auth-server/config"
	oauth2handlers "github.com/jrsteele09/go-auth-server/server/oauth2"
	"github.com/jrsteele09/go-auth-server/server/ui"
	"github.com/jrsteele09/go-auth-server/server/ui/adminsession"
	"github.com/jrsteele09/go-auth-server/tenants"
	"github.com/jrsteele09/go-auth-server/utils"
	"golang.org/x/oauth2"
)

type OidcConfig struct {
	OidcProvider *oidc.Provider
	OAuth2Config *oauth2.Config
	OidcVerifier *oidc.IDTokenVerifier
}

type Server struct {
	mux            *http.ServeMux
	routes         []string
	config         config.Config
	auth           *auth.AuthorizationService
	repos          auth.Repos
	uiHandlers     *ui.UIHandler
	oauth2Handlers *oauth2handlers.Handler

	tenantOidc     map[string]OidcConfig
	tenantOidcLock sync.RWMutex
}

func New(config config.Config, repos auth.Repos, adminSessionRepo adminsession.Repo) (*Server, error) {
	authService, err := auth.NewAuthorizationService(repos, config)
	if err != nil {
		return nil, fmt.Errorf("[Server New] failed to create authorization service: %w", err)
	}

	htmlHandler := ui.NewUIHandler(config, authService, adminSessionRepo, repos.Tenants, repos.Users, repos.RefreshTokens, repos.Clients)

	s := &Server{
		mux:        http.NewServeMux(),
		config:     config,
		repos:      repos,
		auth:       authService,
		uiHandlers: htmlHandler,
		tenantOidc: make(map[string]OidcConfig),
	}
	s.oauth2Handlers = oauth2handlers.NewHandler(authService, config, s.tenantFromHost)

	// Bootstrap: ensure system tenant, admin client, and super admin exist
	ctx := context.Background()
	if err := s.InitialiseSystem(ctx, config); err != nil {
		return nil, fmt.Errorf("[Server New] Failed to initialise the system: %w", err)
	}

	s.initRoutes()
	s.logRoutes()
	return s, nil
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) RegisterRouteHandler(pattern string, handler http.Handler) {
	s.routes = append(s.routes, pattern)
	s.mux.Handle(pattern, handler)
}

func (s *Server) logRoutes() {
	if s.config.GetEnv() != "DEV" {
		return // Skip logging in non-development environments
	}
	for _, route := range s.routes {
		parts := strings.SplitN(route, " ", 2)

		if len(parts) > 1 {
			logRoute(parts[0], parts[1])
		} else {
			logRoute("", parts[0])
		}
	}
}

func logRoute(method, path string) {
	var displayMethod string
	paddedMethod := fmt.Sprintf(" %-7s", method)
	if color, ok := utils.MethodColors[method]; ok {
		displayMethod = color + paddedMethod + utils.ResetColor
	} else {
		displayMethod = utils.Gray + paddedMethod + utils.ResetColor
	}
	log.Printf("[%-19s] %s\n", displayMethod, path)
}

func (s *Server) tenantFromHost(host string) (*tenants.Tenant, error) {
	return utils.TenantFromHost(host, s.config.GetBaseURL(), s.config.GetSystemTenantID(), s.repos.Tenants)
}

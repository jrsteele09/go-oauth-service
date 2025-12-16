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
	"github.com/jrsteele09/go-auth-server/internal/config"
	"github.com/jrsteele09/go-auth-server/server/authflowrepo"
	"github.com/jrsteele09/go-auth-server/server/loginsession"
	"github.com/jrsteele09/go-auth-server/server/ui"
	"golang.org/x/oauth2"
)

type OidcConfig struct {
	OidcProvider *oidc.Provider
	OAuth2Config *oauth2.Config
	OidcVerifier *oidc.IDTokenVerifier
}

type Server struct {
	env           string // Environment (e.g., "development", "production")
	mux           *http.ServeMux
	routes        []string
	fileServer    http.Handler
	config        config.Config
	auth          *auth.AuthorizationService
	repos         auth.Repos
	loginSessions loginsession.Repo
	authState     authflowrepo.Repo

	tenantOidc     map[string]OidcConfig
	tenantOidcLock sync.RWMutex
}

func New(config config.Config, repos auth.Repos, loginSessionRepo loginsession.Repo, authStateRepo authflowrepo.Repo) (*Server, error) {
	authService, err := auth.NewAuthorizationService(repos, config)
	if err != nil {
		return nil, fmt.Errorf("[Server New] failed to create authorization service: %w", err)
	}

	s := &Server{
		mux:           http.NewServeMux(),
		config:        config,
		repos:         repos,
		auth:          authService,
		loginSessions: loginSessionRepo,
		authState:     authStateRepo,
		tenantOidc:    make(map[string]OidcConfig),
	}
	s.env = config.GetEnv()
	s.fileServer = FileServerHandler()

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

func (s *Server) RegisterRouteFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	s.routes = append(s.routes, pattern)
	s.mux.HandleFunc(pattern, handler)
}

func (s *Server) logRoutes() {
	if s.env != "DEV" {
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
	if color, ok := ui.MethodColors[method]; ok {
		displayMethod = color + paddedMethod + ui.ResetColor
	} else {
		displayMethod = ui.Gray + paddedMethod + ui.ResetColor
	}
	log.Printf("[%-19s] %s\n", displayMethod, path)
}

// Helper function to determine the scheme (http/https)
func getScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if scheme := r.Header.Get("X-Forwarded-Proto"); scheme != "" {
		return scheme
	}
	return "http"
}

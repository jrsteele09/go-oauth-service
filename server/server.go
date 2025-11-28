package server

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/jrsteele09/go-auth-server/auth"
	"github.com/jrsteele09/go-auth-server/internal/config"
)

type Server struct {
	env        string // Environment (e.g., "development", "production")
	mux        *http.ServeMux
	routes     []string
	fileServer http.Handler
	config     config.Config
	repos      *auth.Repos
}

func New(config config.Config, repos *auth.Repos) *Server {
	s := &Server{
		mux:    http.NewServeMux(),
		config: config,
		repos:  repos,
	}
	s.env = config.GetEnv()
	s.fileServer = FileServerHandler()

	s.initRoutes()
	s.logRoutes()
	return s
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
	if color, ok := methodColors[method]; ok {
		displayMethod = color + paddedMethod + ResetColor
	} else {
		displayMethod = Gray + paddedMethod + ResetColor
	}
	log.Printf("[%-19s] %s\n", displayMethod, path)
}

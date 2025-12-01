package server

import (
	"fmt"
	"log"
	"net/http"
	"strings"
)

func (s *Server) initRoutes() {
	s.RegisterRouteFunc("GET /auth/login", s.LoginPageHandler())
	s.RegisterRouteFunc("POST /auth/login", s.LoginHandler())
	s.RegisterRouteFunc("GET /auth/forgot-password", s.ForgotPasswordHandler())
	s.RegisterRouteFunc("GET /auth/signup", s.SignupHandler())

	s.RegisterRouteHandler("GET /css/fonts/{file}", ChainMiddleware(s.serveFileHandler(), s.StdMiddleware()...))
	s.RegisterRouteHandler("GET /css/{file}", ChainMiddleware(s.serveFileHandler(), s.StdMiddleware()...))
	s.RegisterRouteHandler("GET /js/{file}", ChainMiddleware(s.serveFileHandler(), s.StdMiddleware()...))
	s.RegisterRouteHandler("GET /{file}", ChainMiddleware(s.serveFileHandler(), s.StdMiddleware()...))
	s.RegisterRouteHandler("GET /", ChainMiddleware(s.serveFileHandler(), s.StdMiddleware()...))
}

func (s *Server) serveFileHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		filePath := strings.TrimPrefix(r.URL.Path, "/")
		if filePath == "" {
			filePath = "index.html"
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

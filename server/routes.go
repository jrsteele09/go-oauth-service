package server

import (
	"net/http"
)

func (s *Server) initRoutes() {
	// Static files (CSS, JS, images) - served from embedded filesystem
	// Must be registered before wildcard routes
	s.RegisterRouteHandler("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(StaticFilesFS()))))

	// Login routes - tenant identified by subdomain (e.g., tenant-id.localhost:8080)
	s.RegisterRouteFunc("GET /auth/login", s.LoginPageHandler())
	s.RegisterRouteFunc("POST /auth/login", s.LoginHandler())
	s.RegisterRouteFunc("GET /auth/forgot-password", s.ForgotPasswordHandler())
	s.RegisterRouteFunc("GET /auth/signup", s.SignupHandler())

	// s.RegisterRouteHandler("GET /privacy", ChainMiddleware(s.privacyHandler(), stdMiddlewareWithCache...))
	// s.RegisterRouteHandler("GET /terms", ChainMiddleware(s.termsHandler(), stdMiddlewareWithCache...))
	// s.RegisterRouteHandler("GET /contact", ChainMiddleware(s.contactHandler(), stdMiddlewareWithCache...))
	// s.RegisterRouteHandler("GET /contact-thanks", ChainMiddleware(s.contactThanksHandler(), stdMiddlewareWithCache...))
	// s.RegisterRouteHandler("GET /contact-rejected", ChainMiddleware(s.contactRejectedHandler(), stdMiddlewareWithCache...))
	// s.RegisterRouteHandler("GET /how-to-play", ChainMiddleware(s.howToPlayHandler(), stdMiddlewareWithCache...))
	// s.RegisterRouteHandler("GET /about", ChainMiddleware(s.aboutHandler(), stdMiddlewareWithCache...))
	// s.RegisterRouteHandler("GET /links", ChainMiddleware(s.linksHandler(), stdMiddlewareWithCache...))
	// s.RegisterRouteHandler("GET /adventure", ChainMiddleware(s.adventureHandler(), stdMiddlewareWithCache...))
	// s.RegisterRouteHandler("GET /arcade", ChainMiddleware(s.arcadeHandler(), stdMiddlewareWithCache...))
	// s.RegisterRouteHandler("GET /gameimages/{image}", ChainMiddleware(s.imageHandler(), stdMiddlewareWithCache...))
	// s.RegisterRouteHandler("GET /game", ChainMiddleware(s.gameHandler(), stdMiddlewareWithCache...))
	// s.RegisterRouteHandler("GET /ads.txt", ChainMiddleware(s.adsTxtFileHandler(), s.StdMiddleware()...))

	// s.RegisterRouteHandler("POST /contact-message", ChainMiddleware(s.postMessageHandler(), stdMiddleWareWithCors...))

}

func (s *Server) serveFileHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.fileServer.ServeHTTP(w, r)
	}
}

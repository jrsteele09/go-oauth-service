package server

import (
	"net/http"
)

func (s *Server) initRoutes() {
	stdMiddleWareWithCors := make([]func(http.HandlerFunc) http.HandlerFunc, 0)
	stdMiddleWareWithCors = append(stdMiddleWareWithCors, s.CorsMiddleware)
	stdMiddleWareWithCors = append(stdMiddleWareWithCors, s.StdMiddleware()...)

	// Add cache and compression middleware to standard middleware for static files
	stdMiddlewareWithCache := append([]func(http.HandlerFunc) http.HandlerFunc{s.CompressionMiddleware, s.CacheMiddleware}, s.StdMiddleware()...)

	s.RegisterRouteHandler("GET /", ChainMiddleware(s.serveFileHandler(), stdMiddlewareWithCache...))
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

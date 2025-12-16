package server

import (
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"strings"
)

func ChainMiddleware(routeFunction http.HandlerFunc, mw ...func(http.HandlerFunc) http.HandlerFunc) http.HandlerFunc {
	chainedHandler := routeFunction
	// Apply middleware in reverse order
	for i := len(mw) - 1; i >= 0; i-- {
		chainedHandler = mw[i](chainedHandler) // Call the middleware function
	}
	return chainedHandler
}

// func ChainMiddleware(routeFunction http.HandlerFunc, mw ...http.HandlerFunc) http.HandlerFunc {
// 	chainedHandler := routeFunction
// 	// Apply middleware in reverse order
// 	for i := len(mw) - 1; i >= 0; i-- {
// 		chainedHandler = mw[i](chainedHandler)
// 	}
// 	return chainedHandler
// }

func (s *Server) HTMLMiddleWare(mw ...func(http.HandlerFunc) http.HandlerFunc) []func(http.HandlerFunc) http.HandlerFunc {
	chainedMiddleWare := []func(http.HandlerFunc) http.HandlerFunc{
		s.WWWRedirectMiddleware,
		s.LoggingMiddleware,
		s.RecoverMiddleware,
		s.FrameSecurityMiddleware,
	}
	chainedMiddleWare = append(chainedMiddleWare, mw...)
	return chainedMiddleWare
}

func (s *Server) APIMiddleware() []func(http.HandlerFunc) http.HandlerFunc {
	return []func(http.HandlerFunc) http.HandlerFunc{
		s.CorsMiddleware,
	}
}

func (s *Server) WWWRedirectMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		// If host starts with www., redirect to non-www
		if strings.HasPrefix(host, "www.") {
			nonWWWHost := strings.TrimPrefix(host, "www.")
			newURL := fmt.Sprintf("https://%s%s", nonWWWHost, r.RequestURI)
			http.Redirect(w, r, newURL, http.StatusMovedPermanently)
			return
		}
		next(w, r)
	}
}

func (s *Server) LoggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.env != "DEV" {
			next(w, r)
			return
		}
		// displayMethod := r.Method

		// if color, ok := methodColors[r.Method]; ok {
		// 	paddedMethod := fmt.Sprintf(" %-7s", r.Method)
		// 	displayMethod = color + paddedMethod + ResetColor
		// }
		// log.Println("["+displayMethod+"]", r.URL.Path)
		logRoute(r.Method, r.URL.Path)
		next(w, r)
	}
}

func (s *Server) FrameSecurityMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Prevent embedding on other sites
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		// Or with CSP (better support nowadays)
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'self'")
		next(w, r)

	}
}

func (s *Server) RecoverMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Recover logic here
		next(w, r)
	}
}

func (s *Server) CorsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")

		// No Origin header = same-origin request, no CORS headers needed
		if origin == "" {
			next(w, r)
			return
		}

		// TODO: Need to retrieve the tenant from the host if per-tenant CORS is needed
		// tenantID, _, err := s.tenantFromHost(r.Host)
		// if err != nil {
		// 	http.Error(w, "cors check - unknown tenant", http.StatusBadRequest)
		// 	return
		// }

		// Check if the origin is allowed
		allowedOrigins := s.config.GetAllowedOrigins()
		isAllowed := allowedOrigins.IsAllowedOrigin(origin)
		isWildcard := allowedOrigins.IsAllowedOrigin("*")

		// Handle preflight (OPTIONS) requests
		if r.Method == "OPTIONS" {
			if isAllowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Allow-Methods", s.config.GetAllowedMethods())
				w.Header().Set("Access-Control-Allow-Headers", s.config.GetAllowedHeaders())
				w.Header().Set("Access-Control-Max-Age", "86400")
			} else if isWildcard {
				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.Header().Set("Access-Control-Allow-Methods", s.config.GetAllowedMethods())
				w.Header().Set("Access-Control-Allow-Headers", s.config.GetAllowedHeaders())
				w.Header().Set("Access-Control-Max-Age", "86400")
				// Don't set Allow-Credentials with wildcard
			}
			// If not allowed and not wildcard, return 200 with no CORS headers
			// Browser will block the actual request
			w.WriteHeader(http.StatusOK)
			return
		}

		// Handle actual requests (non-OPTIONS)
		if isAllowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		} else if isWildcard {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			// Don't set Allow-Credentials with wildcard
		}
		// If not allowed, don't set CORS headers - browser will block

		next(w, r)
	}
}

// gzipResponseWriter wraps http.ResponseWriter to compress response with gzip
type gzipResponseWriter struct {
	io.Writer
	http.ResponseWriter
}

func (w gzipResponseWriter) Write(b []byte) (int, error) {
	return w.Writer.Write(b)
}

// shouldCompressPath determines if a path should be compressed based on file type
func shouldCompressPath(path string) bool {
	// Don't compress binary files that are already optimized or don't compress well
	// if strings.HasSuffix(path, ".wasm") ||
	// 	strings.HasSuffix(path, ".png") ||
	// 	strings.HasSuffix(path, ".jpg") ||
	// 	strings.HasSuffix(path, ".jpeg") ||
	// 	strings.HasSuffix(path, ".gif") ||
	// 	strings.HasSuffix(path, ".ico") ||
	// 	strings.HasSuffix(path, ".webp") ||
	// 	strings.HasSuffix(path, ".mp4") ||
	// 	strings.HasSuffix(path, ".webm") ||
	// 	strings.HasSuffix(path, ".woff") ||
	// 	strings.HasSuffix(path, ".woff2") {
	// 	return false
	// }

	// Compress text-based files (HTML, CSS, JS, JSON, XML, SVG, etc.)
	return true
}

// CompressionMiddleware adds gzip compression to responses
func (s *Server) CompressionMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Check if client accepts gzip encoding
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			next(w, r)
			return
		}

		// Check if we should compress this file type
		if !shouldCompressPath(r.URL.Path) {
			next(w, r)
			return
		}

		// Only compress certain content types
		// We'll check this after the handler runs by wrapping the response writer
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Del("Content-Length") // Length will change after compression

		gz := gzip.NewWriter(w)
		defer gz.Close()

		gzipWriter := gzipResponseWriter{Writer: gz, ResponseWriter: w}
		next(gzipWriter, r)
	}
}

// CacheMiddleware sets appropriate cache headers for static assets
func (s *Server) CacheMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path

		// Determine cache duration based on path and file type
		if isThirdPartyLibrary(path) {
			// Cache Bootstrap, Bootstrap Icons, HTMX for 1 week (these rarely change)
			w.Header().Set("Cache-Control", "public, max-age=604800, must-revalidate")
		} else if isImageAsset(path) {
			// Cache images for 1 hour (you may update these more frequently)
			w.Header().Set("Cache-Control", "public, max-age=3600, must-revalidate")
		} else if isWasmOrGameAsset(path) {
			// Cache WASM and game assets for 5 minutes (quick to load, updated frequently)
			w.Header().Set("Cache-Control", "public, max-age=300, must-revalidate")
		} else if isOtherStaticAsset(path) {
			// Cache other static assets (CSS, JS) for 5 minutes
			w.Header().Set("Cache-Control", "public, max-age=300, must-revalidate")
		} else if isHTML(path) {
			// Cache HTML files for 5 minutes with revalidation
			w.Header().Set("Cache-Control", "public, max-age=300, must-revalidate")
		}

		next(w, r)
	}
}

// Helper function to check if path is a third-party library (Bootstrap, Icons, HTMX)
func isThirdPartyLibrary(path string) bool {
	return strings.Contains(path, "/bootstrap-5.3.6-dist/") ||
		strings.Contains(path, "/bootstrap-icons-1.11.3/") ||
		strings.Contains(path, "/htmx/")
}

// Helper function to check if path is an image in static/images
func isImageAsset(path string) bool {
	imageExtensions := []string{".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico"}
	if !strings.Contains(path, "/images/") {
		return false
	}
	for _, ext := range imageExtensions {
		if len(path) >= len(ext) && path[len(path)-len(ext):] == ext {
			return true
		}
	}
	return false
}

// Helper function to check if path is WASM or game data
func isWasmOrGameAsset(path string) bool {
	wasmExtensions := []string{".wasm", ".data"}
	for _, ext := range wasmExtensions {
		if len(path) >= len(ext) && path[len(path)-len(ext):] == ext {
			return true
		}
	}
	return false
}

// Helper function to check if path is other static asset (CSS, JS, fonts)
func isOtherStaticAsset(path string) bool {
	staticExtensions := []string{".css", ".js", ".woff", ".woff2", ".ttf"}
	for _, ext := range staticExtensions {
		if len(path) >= len(ext) && path[len(path)-len(ext):] == ext {
			return true
		}
	}
	return false
}

// Helper function to check if path is HTML
func isHTML(path string) bool {
	// Check if it ends with .html or is the root path
	return (len(path) >= 5 && path[len(path)-5:] == ".html") || path == "/"
}

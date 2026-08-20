package utils

import (
	"net/http"
	"net/url"
)

// redirectPage helper for htmx-aware success redirects
func RedirectPage(w http.ResponseWriter, r *http.Request, path string) {
	if IsHTMXRequest(r) {
		w.Header().Set("HX-Redirect", path)
		w.WriteHeader(http.StatusNoContent) // 204 - no content, just redirect instruction
		return
	}
	http.Redirect(w, r, path, http.StatusSeeOther)
}

// redirectWithError helper for htmx-aware error redirects
func RedirectWithError(w http.ResponseWriter, r *http.Request, path, errorMsg string) {
	fullPath := path + "?error=" + url.QueryEscape(errorMsg)

	if IsHTMXRequest(r) {
		w.Header().Set("HX-Redirect", fullPath)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	http.Redirect(w, r, fullPath, http.StatusSeeOther)
}

// isHTMXRequest checks if the request was initiated by HTMX
func IsHTMXRequest(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true"
}

// Helper function to determine the scheme (http/https)
func GetScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if scheme := r.Header.Get("X-Forwarded-Proto"); scheme != "" {
		return scheme
	}
	return "http"
}

func ChainMiddleware(routeFunction http.HandlerFunc, mw ...func(http.HandlerFunc) http.HandlerFunc) http.HandlerFunc {
	chainedHandler := routeFunction
	// Apply middleware in reverse order
	for i := len(mw) - 1; i >= 0; i-- {
		chainedHandler = mw[i](chainedHandler) // Call the middleware function
	}
	return chainedHandler
}

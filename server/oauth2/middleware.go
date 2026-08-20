package oauth2

import "net/http"

func (h *Handler) apiMiddleware() []func(http.HandlerFunc) http.HandlerFunc {
	return []func(http.HandlerFunc) http.HandlerFunc{
		h.corsMiddleware,
	}
}

func (h *Handler) corsMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if origin == "" {
			next(w, r)
			return
		}

		allowedOrigins := h.config.GetAllowedOrigins()
		isAllowed := allowedOrigins.IsAllowedOrigin(origin)
		isWildcard := allowedOrigins.IsAllowedOrigin("*")

		if r.Method == http.MethodOptions {
			if isAllowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Credentials", "true")
				w.Header().Set("Access-Control-Allow-Methods", h.config.GetAllowedMethods())
				w.Header().Set("Access-Control-Allow-Headers", h.config.GetAllowedHeaders())
				w.Header().Set("Access-Control-Max-Age", "86400")
			} else if isWildcard {
				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.Header().Set("Access-Control-Allow-Methods", h.config.GetAllowedMethods())
				w.Header().Set("Access-Control-Allow-Headers", h.config.GetAllowedHeaders())
				w.Header().Set("Access-Control-Max-Age", "86400")
			}
			w.WriteHeader(http.StatusOK)
			return
		}

		if isAllowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		} else if isWildcard {
			w.Header().Set("Access-Control-Allow-Origin", "*")
		}

		next(w, r)
	}
}

func chainMiddleware(routeFunction http.HandlerFunc, mw ...func(http.HandlerFunc) http.HandlerFunc) http.HandlerFunc {
	chainedHandler := routeFunction
	for i := len(mw) - 1; i >= 0; i-- {
		chainedHandler = mw[i](chainedHandler)
	}
	return chainedHandler
}

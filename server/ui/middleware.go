package ui

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/jrsteele09/go-auth-server/auth/users"
	"github.com/jrsteele09/go-auth-server/utils"
	"github.com/rs/zerolog/log"
)

func (h *UIHandler) HTMLMiddleWare(mw ...func(http.HandlerFunc) http.HandlerFunc) []func(http.HandlerFunc) http.HandlerFunc {
	chainedMiddleWare := []func(http.HandlerFunc) http.HandlerFunc{
		h.WWWRedirectMiddleware,
		h.LoggingMiddleware,
		h.RecoverMiddleware,
		h.FrameSecurityMiddleware,
	}
	chainedMiddleWare = append(chainedMiddleWare, mw...)
	return chainedMiddleWare
}

func (h *UIHandler) WWWRedirectMiddleware(next http.HandlerFunc) http.HandlerFunc {
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

func (h *UIHandler) LoggingMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if h.config.GetEnv() != "DEV" {
			next(w, r)
			return
		}
		logRoute(r.Method, r.URL.Path)
		next(w, r)
	}
}

func (h *UIHandler) FrameSecurityMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Prevent embedding on other sites
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		// Or with CSP (better support nowadays)
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'self'")
		next(w, r)

	}
}

func (h *UIHandler) RecoverMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		next(w, r)
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

func (h *UIHandler) RequireSessionAuth(enforcePasswordChange bool) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			session, err := h.currentAdminSession(r)
			if err != nil {
				utils.RedirectPage(w, r, RouteAdminLogin)
				return
			}

			user, err := h.users.GetByID(session.TenantID, session.UserID)
			if err != nil || user == nil {
				h.SetAdminSessionCookie(w, r, "", -1)
				utils.RedirectPage(w, r, RouteAdminLogin)
				return
			}

			if user.Blocked || !user.Verified {
				h.SetAdminSessionCookie(w, r, "", -1)
				utils.RedirectPage(w, r, RouteAdminLogin)
				return
			}

			if !user.IsSuperAdmin() && !user.HasTenantRole(session.TenantID, users.RoleTenantAdmin) {
				http.Error(w, "Forbidden: admin access required", http.StatusForbidden)
				return
			}

			if enforcePasswordChange && user.PasswordChangeRequired {
				utils.RedirectPage(w, r, RouteChangePassword+"?required=true")
				return
			}

			session.PasswordChangeRequired = user.PasswordChangeRequired
			ctx := context.WithValue(r.Context(), ContextKeyUserID, session.UserID)
			ctx = context.WithValue(ctx, ContextKeyTenantID, session.TenantID)
			ctx = context.WithValue(ctx, ContextKeySession, session)

			next(w, r.WithContext(ctx))
		}
	}
}

package oauth2

import "net/http"

const authSessionCookieName = "auth_session_id"

func (h *Handler) setAuthSessionCookie(w http.ResponseWriter, r *http.Request, authSessionID string, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name:     authSessionCookieName,
		Value:    authSessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   r.TLS != nil,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

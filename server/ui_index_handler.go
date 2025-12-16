package server

import (
	"net/http"
)

// IndexHandler renders the home page
func (s *Server) IndexHandler() http.HandlerFunc {
	tmpl, err := ParseTemplate("index.html")
	if err != nil {
		panic("Failed to parse index template: " + err.Error())
	}

	return func(w http.ResponseWriter, r *http.Request) {
		data := map[string]interface{}{
			"AppName": s.config.GetAppName(),
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = tmpl.Execute(w, data)
	}
}

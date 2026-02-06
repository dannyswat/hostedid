package middleware

import (
	"net/http"
	"runtime/debug"
)

// Recover recovers from panics and logs the error
func (m *Middleware) Recover(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if err := recover(); err != nil {
				m.log.Error().
					Interface("error", err).
					Str("stack", string(debug.Stack())).
					Str("path", r.URL.Path).
					Str("method", r.Method).
					Msg("panic recovered")

				http.Error(w, `{"error":"internal_server_error","message":"An unexpected error occurred"}`, http.StatusInternalServerError)
			}
		}()

		next.ServeHTTP(w, r)
	})
}

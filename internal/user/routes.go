package user

import (
	"net/http"

	"github.com/Morgrace/auth-system/internal/middleware"
)

func RegisterRoutes(mux *http.ServeMux, h *Handler, authMW *middleware.AuthMiddleware) {
	protect := func(next http.HandlerFunc) http.Handler {
		return authMW.Protect(next)
	}
	mux.Handle("PUT /user/password", protect(h.UpdatePassword))

	mux.Handle("PATCH /user/profile", protect(h.UpdateProfile))

	mux.Handle("DELETE /user", protect(h.SoftDelete))
}

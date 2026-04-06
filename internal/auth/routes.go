package auth

import (
	"net/http"

	"github.com/Morgrace/auth-system/internal/middleware"
)

func RegisterRoutes(mux *http.ServeMux, h *Handler, authMW *middleware.AuthMiddleware) {
	protect := func(next http.HandlerFunc) http.Handler {
		return authMW.Protect(next)
	}
	mux.HandleFunc("POST /auth/register", h.Register)
	mux.HandleFunc("POST /auth/login", h.Login)
	mux.HandleFunc("POST /auth/refresh-token", h.RefreshToken)
	mux.HandleFunc("POST /auth/verify-email", h.VerifyEmail)
	mux.HandleFunc("POST /auth/resend-verification", h.ResendVerification)
	mux.HandleFunc("POST /auth/forgot-password", h.ForgotPassword)
	mux.HandleFunc("POST /auth/reset-password/{token}", h.ResetPassword)

	// Protected:

	mux.Handle("POST /auth/logout", protect(h.Logout))
}

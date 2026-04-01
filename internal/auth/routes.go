package auth

import "net/http"

func RegisterRoutes(mux *http.ServeMux, h *Handler) {
	mux.HandleFunc("POST /auth/register", h.Register)
	mux.HandleFunc("POST /auth/login", h.Login)
	mux.HandleFunc("POST /auth/refresh-token", h.RefreshToken)
	mux.HandleFunc("POST /auth/verify-email", h.VerifyEmail)
	mux.HandleFunc("POST /auth/resend-verification", h.ResendVerification)
	mux.HandleFunc("POST /auth/forgot-password", h.ForgotPassword)
	mux.HandleFunc("POST /auth/reset-password/{token}", h.ResetPassword)

	// Protected:
	mux.HandleFunc("POST /auth/logout", h.Logout)
}

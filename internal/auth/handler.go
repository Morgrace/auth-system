package auth

import (
	"net/http"
	"strings"

	"github.com/Morgrace/auth-system/pkg/utils"
	appErrors "github.com/Morgrace/auth-system/pkg/utils/errors"
)

type Handler struct {
	service Service
}

func NewHandler(service Service) *Handler {
	return &Handler{service: service}
}

// getClientIP extracts the real IP from the request, respecting common proxy headers.
func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}
	return r.RemoteAddr
}

// Register handles POST /api/v1/auth/register
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req RegisterRequest

	if !utils.DecodeAndValidate(w, r, &req) {
		return
	}

	resp, err := h.service.Register(r.Context(), req)
	if err != nil {
		utils.HandleError(w, r, err)
		return
	}
	utils.WriteSuccess(w, r, http.StatusCreated, resp, resp.Message)
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req LoginRequest
	if !utils.DecodeAndValidate(w, r, &req) {
		return
	}

	deviceInfo := r.UserAgent()
	ipAddress := getClientIP(r)

	resp, err := h.service.Login(r.Context(), req, deviceInfo, ipAddress)
	if err != nil {
		utils.HandleError(w, r, err)
		return
	}
	utils.WriteSuccess(w, r, http.StatusOK, resp, "Login successful")

}

func (h *Handler) RefreshToken(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token" validate:"required"`
	}

	if !utils.DecodeAndValidate(w, r, &req) {
		return
	}

	deviceInfo := r.UserAgent()
	ipAddress := getClientIP(r)

	resp, err := h.service.RefreshToken(r.Context(), req.RefreshToken, deviceInfo, ipAddress)
	if err != nil {
		utils.HandleError(w, r, err)
		return
	}
	utils.WriteSuccess(w, r, http.StatusOK, resp, "Token refreshed")
}

func (h *Handler) VerifyEmail(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("token")
	if token == "" {
		utils.HandleError(w, r, appErrors.ErrInvalidInput)
		return
	}
	resp, err := h.service.VerifyEmail(r.Context(), token)
	if err != nil {
		utils.HandleError(w, r, err)
		return
	}
	utils.WriteSuccess(w, r, http.StatusOK, resp, resp.Message)
}

func (h *Handler) ResendVerification(w http.ResponseWriter, r *http.Request) {
	var req ResendVerificationRequest

	if !utils.DecodeAndValidate(w, r, &req) {
		return
	}

	resp, err := h.service.ResendVerification(r.Context(), req)
	if err != nil {
		utils.HandleError(w, r, err)
		return
	}
	utils.WriteSuccess(w, r, http.StatusOK, resp, resp.Message)
}

func (h *Handler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var req ForgotPasswordRequest
	if !utils.DecodeAndValidate(w, r, &req) {
		return
	}

	resp, err := h.service.ForgotPassword(r.Context(), req)
	if err != nil {
		utils.HandleError(w, r, err)
		return
	}
	utils.WriteSuccess(w, r, http.StatusOK, resp, resp.Message)
}

func (h *Handler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	token := r.PathValue("token")

	if token == "" {
		utils.HandleError(w, r, appErrors.ErrInvalidInput)
		return
	}
	var req ResetPasswordRequest
	if !utils.DecodeAndValidate(w, r, &req) {
		return
	}

	resp, err := h.service.ResetPassword(r.Context(), token, req)
	if err != nil {
		utils.HandleError(w, r, err)
		return
	}
	utils.WriteSuccess(w, r, http.StatusOK, resp, resp.Message)

}

func (h *Handler) Logout(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token" validate:"required"`
	}

	if !utils.DecodeAndValidate(w, r, &req) {
		return
	}

	resp, err := h.service.Logout(r.Context(), req.RefreshToken)
	if err != nil {
		utils.HandleError(w, r, err)
		return
	}
	utils.WriteSuccess(w, r, http.StatusOK, resp, resp.Message)
}

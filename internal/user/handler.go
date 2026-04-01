package user

import (
	"net/http"

	"github.com/Morgrace/auth-system/pkg/utils"
	appErrors "github.com/Morgrace/auth-system/pkg/utils/errors"
	"github.com/google/uuid"
)

type contextKey string

const UserIDKey contextKey = "userID"

type Handler struct {
	service Service
}

func NewHandler(service Service) *Handler {
	return &Handler{service: service}
}

func getUserID(r *http.Request) (uuid.UUID, error) {
	id, ok := r.Context().Value(UserIDKey).(uuid.UUID)
	if !ok {
		return uuid.Nil, appErrors.ErrUnauthorized
	}
	return id, nil
}

func (h *Handler) UpdatePassword(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserID(r)
	if err != nil {
		utils.HandleError(w, r, err)
		return
	}

	var req UpdatePasswordRequest
	if !utils.DecodeAndValidate(w, r, &req) {
		return
	}

	resp, err := h.service.UpdatePassword(r.Context(), userID, req)
	if err != nil {
		utils.HandleError(w, r, err)
		return
	}
	utils.WriteSuccess(w, r, http.StatusOK, resp, resp.Message)
}

func (h *Handler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserID(r)
	if err != nil {
		utils.HandleError(w, r, err)
		return
	}

	var req UpdateProfileRequest
	if !utils.DecodeAndValidate(w, r, &req) {
		return
	}
	resp, err := h.service.UpdateProfile(r.Context(), userID, req)
	if err != nil {
		utils.HandleError(w, r, err)
		return
	}
	utils.WriteSuccess(w, r, http.StatusOK, resp, "Profile updated successfully")
}

func (h *Handler) SoftDelete(w http.ResponseWriter, r *http.Request) {
	userID, err := getUserID(r)
	if err != nil {
		utils.HandleError(w, r, err)
		return
	}

	resp, err := h.service.SoftDelete(r.Context(), userID)
	if err != nil {
		utils.HandleError(w, r, err)
		return
	}
	utils.WriteSuccess(w, r, http.StatusOK, resp, resp.Message)
}

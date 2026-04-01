package user

import "net/http"

func RegisterRoutes(mux *http.ServeMux, h *Handler) {
	mux.HandleFunc("PUT /user/password",h.UpdatePassword)
	mux.HandleFunc("PATCH /user/profile",h.UpdateProfile)
	mux.HandleFunc("DELETE /user", h.SoftDelete)
}

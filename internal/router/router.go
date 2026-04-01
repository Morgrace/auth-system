package router

import (
	"net/http"

	"github.com/Morgrace/auth-system/internal/auth"
	"github.com/Morgrace/auth-system/internal/user"
)

func New(authHandler *auth.Handler, userHander *user.Handler) http.Handler {
	mainMux := http.NewServeMux()
	v1 := http.NewServeMux()

	auth.RegisterRoutes(v1, authHandler)
	user.RegisterRoutes(v1, userHander)

	mainMux.Handle("/api/v1/", http.StripPrefix("/api/v1", v1))
	return mainMux
}

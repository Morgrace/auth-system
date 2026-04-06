package router

import (
	"net/http"

	"github.com/Morgrace/auth-system/internal/auth"
	"github.com/Morgrace/auth-system/internal/dashboard"
	"github.com/Morgrace/auth-system/internal/middleware"
	"github.com/Morgrace/auth-system/internal/user"
)

func New(authHandler *auth.Handler, userHander *user.Handler, dashboardHandler *dashboard.Handler, authMW *middleware.AuthMiddleware, roleMW *middleware.RoleMiddleware) http.Handler {
	mainMux := http.NewServeMux()
	v1 := http.NewServeMux()

	auth.RegisterRoutes(v1, authHandler, authMW)
	user.RegisterRoutes(v1, userHander, authMW)
	dashboard.RegisterRoutes(v1, dashboardHandler, authMW, roleMW)

	mainMux.Handle("/api/v1/", http.StripPrefix("/api/v1", v1))
	return mainMux
}

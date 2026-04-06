package dashboard

import (
	"net/http"

	"github.com/Morgrace/auth-system/internal/middleware"
	"github.com/Morgrace/auth-system/pkg/utils"
)

func RegisterRoutes(mux *http.ServeMux, h *Handler, authMW *middleware.AuthMiddleware, roleMW *middleware.RoleMiddleware) {
	// Public dashboard – any authenticated user
	mux.Handle("GET /public/dashboard", authMW.Protect(http.HandlerFunc(h.PublicDashboard)))

	// User dashboard – requires role "user" or higher
	mux.Handle("GET /user/dashboard", authMW.Protect(http.HandlerFunc(h.UserDashboard)))

	// Admin dashboard – requires role "admin" or "super_admin"
	mux.Handle("GET /admin/dashboard", utils.ApplyMiddlewares(http.HandlerFunc(h.AdminDashboard), authMW.Protect, roleMW.Require(middleware.RoleAdmin, middleware.RoleSuperAdmin)))

	// Super Admin dashboard – requires role "super_admin"
	mux.Handle("GET /super-admin/dashboard", authMW.Protect(roleMW.Require(middleware.RoleSuperAdmin)(http.HandlerFunc(h.SuperAdminDashboard))))
}

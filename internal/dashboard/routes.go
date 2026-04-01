package dashboard

// import (
//     "net/http"

// )

// func RegisterRoutes(mux *http.ServeMux, h *Handler) {
//     // Public dashboard – any authenticated user
//     mux.Handle("GET /public/dashboard", authMW.Protect(http.HandlerFunc(h.PublicDashboard)))

//     // User dashboard – requires role "user" or higher
//     mux.Handle("GET /user/dashboard", authMW.Protect(roleMW.RequireAny("user", "admin", "super_admin")(http.HandlerFunc(h.UserDashboard))))

//     // Admin dashboard – requires role "admin" or "super_admin"
//     mux.Handle("GET /admin/dashboard", authMW.Protect(roleMW.RequireAny("admin", "super_admin")(http.HandlerFunc(h.AdminDashboard))))

//     // Super Admin dashboard – requires role "super_admin"
//     mux.Handle("GET /super-admin/dashboard", authMW.Protect(roleMW.Require("super_admin")(http.HandlerFunc(h.SuperAdminDashboard))))
// }

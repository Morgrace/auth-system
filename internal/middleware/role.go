package middleware

import (
	"net/http"
	"slices"

	"github.com/Morgrace/auth-system/pkg/utils"
	appErrors "github.com/Morgrace/auth-system/pkg/utils/errors"
)

type RoleMiddleware struct{}

func NewRoleMiddleware() *RoleMiddleware {
	return &RoleMiddleware{}
}

func (rm *RoleMiddleware) Require(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userRole, ok := r.Context().Value(UserRoleKey).(string)
			if !ok || !slices.Contains(roles, userRole) {
				utils.HandleError(w, r, appErrors.ErrForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

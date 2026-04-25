package middleware

import (
	"net/http"
	"slices"

	"github.com/Morgrace/auth-system/internal/types"
	"github.com/Morgrace/auth-system/pkg/utils"
	appErrors "github.com/Morgrace/auth-system/pkg/utils/errors"
)

type RoleMiddleware struct{}

func NewRoleMiddleware() *RoleMiddleware {
	return &RoleMiddleware{}
}

func (rm *RoleMiddleware) Require(roles ...types.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			userRole, ok := r.Context().Value(types.UserRoleKey).(types.Role)
			if !ok || !slices.Contains(roles, userRole) {
				utils.HandleError(w, r, appErrors.ErrForbidden, "You do not have permission to access this resource")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

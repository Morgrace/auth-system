package middleware

import (
	"context"
	"log"
	"net/http"
	"strings"

	"github.com/Morgrace/auth-system/internal/types"
	"github.com/Morgrace/auth-system/pkg/utils"
	appErrors "github.com/Morgrace/auth-system/pkg/utils/errors"
	"github.com/google/uuid"
)

type AuthMiddleware struct {
	jwtManager *utils.JWTManager
}

func NewAuthMiddleware(jwtManager *utils.JWTManager) *AuthMiddleware {
	return &AuthMiddleware{jwtManager: jwtManager}
}

func (am *AuthMiddleware) Protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			utils.HandleError(w, r, appErrors.ErrUnauthorized, "Missing authorization header")
			return
		}
		parts := strings.Fields(authHeader)
		if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
			utils.HandleError(w, r, appErrors.ErrUnauthorized, "Invalid authorization header format")
			return
		}
		tokenString := parts[1]

		// Verify token
		claims, err := am.jwtManager.VerifyToken(tokenString)
		if err != nil {
			utils.HandleError(w, r, appErrors.ErrUnauthorized, "Invalid or expired token")
			return
		}

		userID, err := uuid.Parse(claims.UserID)
		if err != nil {
			log.Printf("middleware protect: parse uuid:%v", err)
			utils.WriteServerError(w, r, appErrors.CodeInternalServer, "Something went wrong")
			return
		}

		ctx := context.WithValue(r.Context(), types.UserIDKey, userID)
		ctx = context.WithValue(ctx, types.UserRoleKey, claims.Role)
		r = r.WithContext(ctx)

		next.ServeHTTP(w, r)
	})
}

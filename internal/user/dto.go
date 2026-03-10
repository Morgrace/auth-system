package user

import (
	"github.com/Morgrace/auth-system/internal/auth"
)
type UpdatePasswordRequest struct {
	CurrentPassword string 	`json:"current_password" validate:"required"`
	auth.Password
}
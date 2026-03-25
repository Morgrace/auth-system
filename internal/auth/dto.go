package auth

import (
	"github.com/Morgrace/auth-system/internal/user"
)

// Requests
type RegisterRequest struct {
	FirstName string `json:"first_name" validate:"required,min=2,max=50"`
	LastName  string `json:"last_name" validate:"required,min=2,max=50"`
	Email     string `json:"email" validate:"app_email"`
	Password  string `json:"password" validate:"app_password"`
}

type LoginRequest struct {
	Email string `json:"email" validate:"app_email"`
	// Security Fix: Do not use app_password here. See AppSec note below.
	Password string `json:"password" validate:"required"`
}

type ResendVerificationRequest struct {
	Email string `json:"email" validate:"app_email"`
}

type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"app_email"`
}

type ResetPasswordRequest struct {
	Password string `json:"password" validate:"app_password"`
	// eqfield matches the exact struct field name (Password), not the JSON tag
	PasswordConfirm string `json:"password_confirm" validate:"required,eqfield=Password"`
}

type AuthResponse struct {
	AccessToken  string            `json:"access_token"`
	RefreshToken string            `json:"refresh_token"`
	User         user.UserResponse `json:"user"`
}

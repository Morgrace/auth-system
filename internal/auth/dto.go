package auth

import (
	"time"

	"github.com/google/uuid"
)

// Reusable embedded types
type Email struct {
	Email string `json:"email" validate:"required,email,max=255"`
}
type Password struct {
	Password string `json:"password" validate:"required,min=8,max=72"`
}

// Requests
type RegisterRequest struct {
	FirstName string `json:"first_name" validate:"required,min=2,max=50"`
	LastName  string `json:"last_name" validate:"required,min=2,max=50"`
	Email
	Password
}

type LoginRequest struct {
	Email
	Password
}

type ResendVerificationRequest struct {
	Email
}
type ForgotPasswordRequest struct {
	Email
}

type ResetPasswordRequest struct {
	Password
	PasswordConfirm string `json:"password_confirm" validate:"required,eqfield=Password"`
}

// Responses
type UserResponse struct {
	ID              uuid.UUID `json:"id"`
	FirstName       string    `json:"first_name"`
	LastName        string    `json:"last_name"`
	Email           string    `json:"email"`
	Role            string    `json:"role"`
	IsEmailVerified bool      `json:"is_email_verified"`
	IsActive        bool      `json:"is_active"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

type AuthResponse struct {
	AccessToken string       `json:"access_token"`
	User        UserResponse `json:"user"`
}

type MessageResponse struct {
	Message string `json:"message"`
}

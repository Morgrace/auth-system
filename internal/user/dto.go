package user

import (
	"time"

	"github.com/google/uuid"
)

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

type UpdatePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required"`
	Password        string `json:"password" validate:"app_password"`
}

// UpdateProfileRequest is for updating user profile.
type UpdateProfileRequest struct {
    FirstName *string `json:"first_name" validate:"omitempty,min=2,max=50"`
    LastName  *string `json:"last_name" validate:"omitempty,min=2,max=50"`
}

type MessageResponse struct {
	Message string `json:"message"`
}

func ToUserResponse(u *User) UserResponse {
	return UserResponse{
		ID:              u.ID,
		FirstName:       u.FirstName,
		LastName:        u.LastName,
		Email:           u.Email,
		Role:            string(u.Role),
		IsEmailVerified: u.IsEmailVerified,
		IsActive:        u.IsActive,
		CreatedAt:       u.CreatedAt,
		UpdatedAt:       u.UpdatedAt,
	}
}

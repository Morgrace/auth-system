package user

import (
	"context"

	"github.com/Morgrace/auth-system/internal/auth"
	"github.com/google/uuid"
)

// Service defines user profile management operations.
type Service interface {
	UpdateProfile(ctx context.Context, userID uuid.UUID, req UpdatePasswordRequest) (*UserResponse, error)

	UpdatePassword(ctx context.Context, userID uuid.UUID, req UpdatePasswordRequest) (*MessageResponse, error)

	SoftDelete(ctx context.Context, userID uuid.UUID) (*MessageResponse, error)
}

type serivce struct {
	userRepo Repository
	authRepo auth.Repository
}

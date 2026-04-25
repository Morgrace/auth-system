package user

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/Morgrace/auth-system/pkg/utils"
	appErrors "github.com/Morgrace/auth-system/pkg/utils/errors"
	"github.com/google/uuid"
)

type RevokeTokensFunc func(ctx context.Context, userID uuid.UUID) error

// Service defines user profile management operations.
type Service interface {
	UpdateProfile(ctx context.Context, userID uuid.UUID, req UpdateProfileRequest) (*UserResponse, error)

	UpdatePassword(ctx context.Context, userID uuid.UUID, req UpdatePasswordRequest) (*MessageResponse, error)

	SoftDelete(ctx context.Context, userID uuid.UUID) (*MessageResponse, error)

	GetUser(ctx context.Context, userID uuid.UUID) (*UserResponse, error)
}

type service struct {
	userRepo     Repository
	revokeTokens RevokeTokensFunc
}

func NewService(userRepo Repository, revokeTokens RevokeTokensFunc) Service {
	return &service{
		userRepo:     userRepo,
		revokeTokens: revokeTokens,
	}
}

func (s *service) GetUser(ctx context.Context, userID uuid.UUID) (*UserResponse, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("service: get user: %w", err)
	}
	if user == nil || !user.IsActive {
		return nil, appErrors.NewNotFound("User does not exist")
	}

	resp := ToUserResponse(user)
	return &resp, nil

}

func (s *service) UpdateProfile(ctx context.Context, userID uuid.UUID, req UpdateProfileRequest) (*UserResponse, error) {
	u, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("service: update profile get user: %w", err)
	}

	if u == nil || !u.IsActive {
		return nil, appErrors.ErrNotFound
	}

	// Apply updates if provided
	if req.FirstName != nil {
		u.FirstName = *req.FirstName
	}
	if req.LastName != nil {
		u.LastName = *req.LastName
	}

	u.UpdatedAt = time.Now()
	if err := s.userRepo.Update(ctx, u); err != nil {
		return nil, fmt.Errorf("service: update profile update user: %w", err)
	}
	resp := ToUserResponse(u)
	return &resp, nil
}

func (s *service) UpdatePassword(ctx context.Context, userID uuid.UUID, req UpdatePasswordRequest) (*MessageResponse, error) {
	// Get current user
	u, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("service: update password get user: %w", err)
	}
	if u == nil || !u.IsActive {
		return nil, appErrors.ErrNotFound
	}

	// Verify current password
	ok, err := utils.CheckPassword(req.CurrentPassword, u.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("service: update password check current: %w", err)
	}
	if !ok {
		return nil, appErrors.NewInvalidInput("current password is incorrect")
	}

	// Hash new password
	newHash, err := utils.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("service: update password hash new: %w", err)
	}

	// Update user
	now := time.Now()
	u.PasswordHash = newHash
	u.PasswordChangedAt = &now
	u.UpdatedAt = now
	if err := s.userRepo.Update(ctx, u); err != nil {
		return nil, fmt.Errorf("service: update password update user: %w", err)
	}

	// Revoke all refresh tokens for this user to force re-login
	if err := s.revokeTokens(ctx, u.ID); err != nil {
		log.Printf("failedt to revoke user token: %v", err)
	}
	return &MessageResponse{Message: "Password updated successfully"}, nil
}

func (s *service) SoftDelete(ctx context.Context, userID uuid.UUID) (*MessageResponse, error) {
	// Get current user (ensure exists and is active)
	u, err := s.userRepo.GetByID(ctx, userID)

	if err != nil {
		return nil, fmt.Errorf("service: soft delete get user: %w", err)
	}

	if u == nil || !u.IsActive {
		return nil, appErrors.ErrNotFound
	}

	if err := s.userRepo.SoftDelete(ctx, userID); err != nil {
		return nil, fmt.Errorf("service: soft delete: %w", err)
	}

	if err := s.revokeTokens(ctx, userID); err != nil {
		log.Printf("failed to revoke user token: %v", err)
	}
	return &MessageResponse{Message: "Account deactivated successfully"}, nil
}

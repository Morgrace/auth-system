package auth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// Repository defines the data operations for refresh tokens.
type Repository interface {
	// Create stores a new refresh token.
	Create(ctx context.Context, token *RefreshToken) error
	// GetByTokenHash retrieves a refresh token by its hashed value.
	// Returns nil, nil if not found.
	GetByTokenHash(ctx context.Context, tokenHash string) (*RefreshToken, error)
	// Revoke marks a specific refresh token as revoked.
	Revoke(ctx context.Context, id uuid.UUID) error
	// RevokeAllForUser revokes all active refresh tokens for a user.
	RevokeAllForUser(ctx context.Context, userID uuid.UUID) error
	// DeleteExpired removes all expired refresh tokens from the database.
	DeleteExpired(ctx context.Context) error
}

type repository struct {
	db *sqlx.DB
}

func NewRepository(db *sqlx.DB) Repository {
	return &repository{db: db}
}

// Create inserts a new refresh token.
func (r *repository) Create(ctx context.Context, token *RefreshToken) error {
	query := `INSERT INTO refresh_tokens (
	id, user_id, token_hash, device_info, ip_address, expires_at, is_revoked, created_at)
	VALUES (
	:id, :user_id, :token_hash, :device_info, :ip_address, :expires_at, :is_revoked, :created_at)`

	_, err := r.db.NamedExecContext(ctx, query, token)
	if err != nil {
		return fmt.Errorf("failed to create refresh token: %w", err)
	}
	return nil
}

// GetByTokenHash retrieves a refresh token by its hashed value.
// Returns nil, nil if not found.
func (r *repository) GetByTokenHash(ctx context.Context, tokenHash string) (*RefreshToken, error) {
	var token RefreshToken
	query := `SELECT * FROM refresh_tokens WHERE token_hash = $1`
	err := r.db.GetContext(ctx, &token, query, tokenHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get refresh token by hash: %w", err)
	}
	return &token, nil
}

// Revoke marks a specific refresh token as revoked.
func (r *repository) Revoke(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE refresh_tokens SET is_revoked = true WHERE id = $1`
	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to revoke refresh token %s: %w", id, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("failed to get rows affected after revoke: %w", err)
	}

	if rows == 0 {
		// This could be because the token doesn't exist or was already revoked.
		// Returning a specific error might help the service layer decide.
		return fmt.Errorf("refresh token %s not found or already revoked", id)
	}
	return nil

}

// RevokeAllForUser revokes all active (non‑revoked, not expired) refresh tokens for a user.
// This is typically used after a password change or when token reuse is detected.
func (r *repository) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	query := `UPDATE refresh_tokens SET is_revoked = true WHERE user_id = $1 AND is_revoked =false AND expires_at > NOW()`
	_, err := r.db.ExecContext(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("failed to revoke all refresh tokens for user %s: %w", userID, err)
	}
	return nil
}

// DeleteExpired removes all expired refresh tokens from the database.
// This can be called periodically by a background job.
func (r *repository) DeleteExpired(ctx context.Context) error {
	query := `DELETE FROM refresh_tokens WHERE expires_at < NOW()`
	_, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return fmt.Errorf("failed to delete expired refresh tokens: %w", err)
	}
	return nil
}

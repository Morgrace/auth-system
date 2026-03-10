package user

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// Repository defines all database operations for users
type Repository interface {
	Create(ctx context.Context, user *User) (*User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	GetByEmailVerificationToken(ctx context.Context, tokenHash string) (*User, error)
	GetByPasswordResetToken(ctx context.Context, tokenHash string) (*User, error)
	Update(ctx context.Context, user *User) error
	SoftDelete(ctx context.Context, id uuid.UUID) error
}

type repository struct {
	db *sqlx.DB
}

func NewRepository(db *sqlx.DB) Repository {
	return &repository{
		db: db,
	}
}

// GetByPasswordResetToken retrieves a user by the hashed password reset token.
// Returns nil, nil if not found.
func (r *repository) GetByPasswordResetToken(ctx context.Context, tokenHash string) (*User, error) {
	var user User
	query := `SELECT * FROM users WHERE password_reset_token = $1 AND deleted_at IS NULL`
	err := r.db.GetContext(ctx, &user, query, tokenHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get user by password reset token: %w", err)
	}
	return &user, nil
}

func (r *repository) GetByID(ctx context.Context, id uuid.UUID) (*User, error) {
	var user User
	query := `SELECT * FROM users WHERE id = $1 AND deleted_at IS NULL`

	err := r.db.GetContext(ctx, &user, query, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("Failed to get user by ID %s: %w", id, err)
	}
	return &user, nil
}

// Create inserts a new user record.
func (r *repository) Create(ctx context.Context, user *User) (*User, error) {
	query := `INSERT INTO users (
	id, first_name, last_name, email, role,
	is_email_verified, email_verification_token, email_verification_expires,
	password_hash, password_changed_at, password_reset_token, password_reset_expires,
	is_active, created_at, updated_at, deleted_at)
	VALUES (
	:id, :first_name, :last_name, :email, :role,
	:is_email_verified, :email_verification_token, :email_verification_expires,
	:password_hash, :password_changed_at, :password_reset_token, :password_reset_expires,
	:is_active, :created_at, :updated_at, :deleted_at)
	RETURNING *`

	rows, err := r.db.NamedQueryContext(ctx, query, user)
	if err != nil {
		return nil, fmt.Errorf("Failed to create user: %w", err)
	}
	defer rows.Close()

	if rows.Next() {
		if err := rows.StructScan(user); err != nil {
			return nil, fmt.Errorf("Failed to scan created user: %w", err)
		}
	} else {
		return nil, fmt.Errorf("No rows returned after insert")
	}
	return user, nil
}

// GetByEmail retrieves a user by email. Returns nil, nil if not found.
func (r *repository) GetByEmail(ctx context.Context, email string) (*User, error) {
	var user User

	query := `SELECT * FROM users WHERE email = $1 AND deleted_at IS NULL`
	err := r.db.GetContext(ctx, &user, query, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("Failed to get user by email %s: %w", email, err)
	}
	return &user, nil
}

// GetByEmailVerificationToken retrieves a user by the hashed email verification token.
// Returns nil, nil if not found.
func (r *repository) GetByEmailVerificationToken(ctx context.Context, tokenHash string) (*User, error) {
	var user User
	query := `SELECT * FROM users WHERE email_verification_token = $1 AND deleted_at IS NULL`
	err := r.db.GetContext(ctx, &user, query, tokenHash)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, fmt.Errorf("Failed to get user by email verification token: %w", err)
	}
	return &user, nil
}

// Update updates an existing user. It expects the user to already have updated_at set or will use current time.
func (r *repository) Update(ctx context.Context, user *User) error {
	// Ensure updated_at is set to now if not already set
	if user.UpdatedAt.IsZero() {
		user.UpdatedAt = time.Now()
	}
	query := `
        UPDATE users SET
            first_name = :first_name,
            last_name = :last_name,
            email = :email,
            role = :role,
            is_email_verified = :is_email_verified,
            email_verification_token = :email_verification_token,
            email_verification_expires = :email_verification_expires,
            password_hash = :password_hash,
            password_changed_at = :password_changed_at,
            password_reset_token = :password_reset_token,
            password_reset_expires = :password_reset_expires,
            is_active = :is_active,
            updated_at = :updated_at,
            deleted_at = :deleted_at
        WHERE id = :id AND deleted_at IS NULL
    `
	result, err := r.db.NamedExecContext(ctx, query, user)
	if err != nil {
		return fmt.Errorf("Failed to update user %s: %w", user.ID, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("Failed to get rows affected after update: %w", err)
	}
	if rows == 0 {
		// This means the user was not found (or was soft-deleted)
		return fmt.Errorf("user %s not found or already deleted", user.ID)
	}
	return nil
}

func (r *repository) SoftDelete(ctx context.Context, id uuid.UUID) error {
	query := `UPDATE users SET deleted_at = NOW(), is_active = false, updated_at = NOW() WHERE id = $1 AND deleted_at IS NULL`
	result, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("Failed to soft delete user %s: %w", id, err)
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("Failed to get rows affected after soft delete: %w", err)
	}
	if rows == 0 {
		return fmt.Errorf("user %s not found or already deleted", id)
	}
	return nil
}

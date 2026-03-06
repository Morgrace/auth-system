package user

import (
	"context"

	"github.com/google/uuid"
	"github.com/jmoiron/sqlx"
)

// Repository defines all database operations for users
type Repository interface {
	Create(ctx context.Context, user *User) (*User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*User, error)
	GetByEmail(ctx context.Context, email string) (*User, error)
	GetByEmailVerificationToken(ctx context.Context, tokenHash string) (*User, error)
	Update(ctx context.Context, user *User) error
	SoftDelete(ctx context.Context, id uuid.UUID) error
}

type repository struct {
	db *sqlx.DB
}

// func NewRepository(db *sqlx.DB) Repository {
// 	return &repository{
// 		db: db,
// 	}
// }

// Create inserts a new user record.

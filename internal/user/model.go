package user

import (
	"time"

	"github.com/Morgrace/auth-system/internal/types"
	"github.com/google/uuid"
)



type User struct {
	ID                       uuid.UUID  `db:"id" json:"id"`
	FirstName                string     `db:"first_name" json:"first_name"`
	LastName                 string     `db:"last_name" json:"last_name"`
	Email                    string     `db:"email" json:"email"`
	Role                     types.Role       `db:"role" json:"role"`
	IsEmailVerified          bool       `db:"is_email_verified" json:"is_email_verified"`
	EmailVerificationToken   *string    `db:"email_verification_token" json:"-"` // hash, not exposed
	EmailVerificationExpires *time.Time `db:"email_verification_expires" json:"-"`
	PasswordHash             string     `db:"password_hash" json:"-"`
	PasswordChangedAt        *time.Time `db:"password_changed_at" json:"-"`
	PasswordResetToken       *string    `db:"password_reset_token" json:"-"`
	PasswordResetExpires     *time.Time `db:"password_reset_expires" json:"-"`
	IsActive                 bool       `db:"is_active" json:"is_active"`
	CreatedAt                time.Time  `db:"created_at" json:"created_at"`
	UpdatedAt                time.Time  `db:"updated_at" json:"updated_at"`
	DeletedAt                *time.Time `db:"deleted_at" json:"deleted_at,omitempty"`
}

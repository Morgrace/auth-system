package auth

import (
	"time"

	"github.com/google/uuid"
)

type RefreshToken struct {
	ID         uuid.UUID `db:"id" json:"id"`
	UserID     uuid.UUID `db:"user_id" json:"user_id"`
	TokenHash  string    `db:"token_hash" json:"-"` // hash, never expose
	DeviceInfo *string   `db:"device_info" json:"device_info,omitempty"`
	IPAddress  *string   `db:"ip_address" json:"ip_address,omitempty"`
	ExpiresAt  time.Time `db:"expires_at" json:"expires_at"`
	IsRevoked  bool      `db:"is_revoked" json:"-"`
	CreatedAt  time.Time `db:"created_at" json:"created_at"`
}

package models

import "time"

// RefreshToken represents a refresh token stored in the database.
type RefreshToken struct {
	TokenHash      string
	UserID         int64
	AppID          int
	CreatedAt      time.Time
	ExpiresAt      time.Time
	RevokedAt      *time.Time
	ReplacedByHash *string
}

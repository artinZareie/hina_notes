package models

import (
	"time"

	"gorm.io/gorm"
)

type EmailVerificationToken struct {
	gorm.Model
	UserID    uint      `gorm.Index;not null`
	TokenHash string    `gorm.Size(64);uniqueIndex;not null`
	ExpiresAt time.Time `gorm.Index;not null`
	UsedAt    *time.Time
}

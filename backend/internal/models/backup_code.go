package models

import (
	"time"

	"gorm.io/gorm"
)

type UserBackupCode struct {
	gorm.Model
	UserID   uint       `gorm:"index;not null"`
	CodeHash string     `gorm:"not null"`
	UsedAt   *time.Time `gorm:"index"`
}

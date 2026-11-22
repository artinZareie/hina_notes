package models

import (
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Email               string     `gorm:"uniqueIndex;not null"`
	Name                string     `gorm:"not null"`
	Password            string     `gorm:"column:password"`
	EmailVerifiedAt     *time.Time `gorm:"column:email_verified_at"`
	TOTPEnabled         bool       `gorm:"column:totp_enabled;not null;default:false"`
	TOTPSecretEncrypted string     `gorm:"column:totp_secret_encrypted"`
	TOTPEnabledAt       *time.Time `gorm:"column:totp_enabled_at"`
}

func (u *User) SetPassword(plain string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(plain), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	u.Password = string(hash)
	return nil
}

func (u *User) CheckPassword(plain string) bool {
	if u.Password == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(u.Password), []byte(plain)) == nil
}

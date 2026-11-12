package models

import (
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Email    string `gorm:"uniqueIndex;not null"`
	Name     string `gorm:"not null"`
	Password string `gorm:"not null"`
}

func (u *User) BeforeSave(tx *gorm.DB) error {
	if u.Password == "" {
		return nil
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(u.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	u.Password = string(hash)
	return nil
}

package database

import (
	"fmt"

	"github.com/artinZareie/hina_notes/backend/internal/models"
	"gorm.io/gorm"
)

var allModels = []any{
	&models.User{},
	&models.UserBackupCode{},
	&models.EmailVerificationToken{},
}

func AutoMigrate(db *gorm.DB) error {
	if err := db.AutoMigrate(allModels...); err != nil {
		return fmt.Errorf("auto-migrate: %w", err)
	}
	return nil
}

package services

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/artinZareie/hina_notes/backend/internal/dto"
	"github.com/artinZareie/hina_notes/backend/internal/models"

	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

var (
	ErrEmailTaken         = errors.New("email is already registered")
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrUserNotFound       = errors.New("user not found")
)

var (
	ErrTOTPAlreadyEnabled = errors.New("two-factor authentication is already enabled")
	ErrTOTPNotEnabled     = errors.New("two-factor authentication is not enabled")
	ErrInvalidTOTPCode    = errors.New("invalid two-factor or recovery code")
	ErrNoPendingTOTP      = errors.New("no pending two-factor setup found")
)

type UserService struct {
	db     *gorm.DB
	aesKey []byte
}

func NewUserService(db *gorm.DB, totpKey string) (*UserService, error) {
	key, err := ParseAES256Key(totpKey)
	if err != nil {
		return nil, err
	}
	return &UserService{db: db, aesKey: key}, nil
}

func (s *UserService) SayHello(_ context.Context) (string, error) {
	return "welcome!", nil
}

func (s *UserService) Register(ctx context.Context, req dto.RegisterRequest) (*models.User, error) {
	email := strings.ToLower(strings.TrimSpace(req.Email))
	name := strings.TrimSpace(req.Name)

	var existing models.User

	err := s.db.WithContext(ctx).Where("email = ?", email).First(&existing).Error
	if err == nil {
		return nil, ErrEmailTaken
	}

	if !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, err
	}

	user := &models.User{
		Email: email,
		Name:  name,
	}

	if err := user.SetPassword(req.Password); err != nil {
		return nil, err
	}

	if err := s.db.WithContext(ctx).Create(user).Error; err != nil {
		return nil, err
	}

	return user, nil
}

func (s *UserService) Login(ctx context.Context, req dto.LoginRequest) (*models.User, error) {
	email := strings.ToLower(strings.TrimSpace(req.Email))

	var user models.User
	err := s.db.WithContext(ctx).Where("email = ?", email).First(&user).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if !user.CheckPassword(req.Password) {
		return nil, ErrInvalidCredentials
	}

	return &user, nil
}

func (s *UserService) GetByID(ctx context.Context, id uint) (*models.User, error) {
	var user models.User
	err := s.db.WithContext(ctx).First(&user, id).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &user, nil
}

func (s *UserService) SetupTOTP(ctx context.Context, userID uint) (secret string, otpauthURL string, err error) {
	user, err := s.GetByID(ctx, userID)
	if err != nil {
		return "", "", err
	}
	if user.TOTPEnabled {
		return "", "", ErrTOTPAlreadyEnabled
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "HinaNotes",
		AccountName: user.Email,
	})
	if err != nil {
		return "", "", err
	}

	return key.Secret(), key.URL(), nil
}

func (s *UserService) EnableTOTP(ctx context.Context, userID uint, pendingSecret, code string) ([]string, error) {
	if strings.TrimSpace(pendingSecret) == "" {
		return nil, ErrNoPendingTOTP
	}

	user, err := s.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user.TOTPEnabled {
		return nil, ErrTOTPAlreadyEnabled
	}

	if !ValidateTOTPWithSkew(strings.TrimSpace(code), pendingSecret, 1) {
		return nil, ErrInvalidTOTPCode
	}

	encryptedSecret, err := EncryptSecret(s.aesKey, pendingSecret)
	if err != nil {
		return nil, err
	}

	plainCodes, hashedCodes, err := GenerateRecoveryCodes(recoveryCodeCount)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", user.ID).Delete(&models.UserBackupCode{}).Error; err != nil {
			return err
		}

		backupRows := make([]models.UserBackupCode, 0, len(hashedCodes))
		for _, h := range hashedCodes {
			backupRows = append(backupRows, models.UserBackupCode{
				UserID:   user.ID,
				CodeHash: h,
			})
		}
		if err := tx.Create(&backupRows).Error; err != nil {
			return err
		}

		return tx.Model(&models.User{}).
			Where("id = ?", user.ID).
			Updates(map[string]any{
				"totp_enabled":          true,
				"totp_secret_encrypted": encryptedSecret,
				"totp_enabled_at":       &now,
			}).Error
	})
	if err != nil {
		return nil, err
	}

	return plainCodes, nil
}

func (s *UserService) VerifyTOTPOrRecovery(ctx context.Context, userID uint, code string) error {
	user, err := s.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if !user.TOTPEnabled {
		return ErrTOTPNotEnabled
	}

	secret, err := DecryptSecret(s.aesKey, user.TOTPSecretEncrypted)
	if err != nil {
		return err
	}

	trimmed := strings.TrimSpace(code)
	if ValidateTOTPWithSkew(trimmed, secret, 1) {
		return nil
	}

	normalized := NormalizeRecoveryCode(trimmed)
	var codes []models.UserBackupCode
	if err := s.db.WithContext(ctx).
		Where("user_id = ? AND used_at IS NULL", user.ID).
		Find(&codes).Error; err != nil {
		return err
	}

	for _, c := range codes {
		if bcrypt.CompareHashAndPassword([]byte(c.CodeHash), []byte(normalized)) == nil {
			now := time.Now().UTC()
			res := s.db.WithContext(ctx).
				Model(&models.UserBackupCode{}).
				Where("id = ? AND user_id = ? AND used_at IS NULL", c.ID, user.ID).
				Update("used_at", &now)
			if res.Error != nil {
				return res.Error
			}
			if res.RowsAffected == 1 {
				return nil
			}
		}
	}

	return ErrInvalidTOTPCode
}

func (s *UserService) DisableTOTP(ctx context.Context, userID uint) error {
	user, err := s.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if !user.TOTPEnabled {
		return ErrTOTPNotEnabled
	}

	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", user.ID).Delete(&models.UserBackupCode{}).Error; err != nil {
			return err
		}
		return tx.Model(&models.User{}).
			Where("id = ?", user.ID).
			Updates(map[string]any{
				"totp_enabled":          false,
				"totp_secret_encrypted": "",
				"totp_enabled_at":       nil,
			}).Error
	})
}

func (s *UserService) DeleteUser(ctx context.Context, userID uint) error {
	return s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ?", userID).Delete(&models.UserBackupCode{}).Error; err != nil {
			return err
		}

		if err := tx.Delete(&models.User{}, userID).Error; err != nil {
			return err
		}

		return nil
	})
}

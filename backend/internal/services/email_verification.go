package services

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/artinZareie/hina_notes/backend/internal/mail"
	"github.com/artinZareie/hina_notes/backend/internal/mail/mailables"
	"github.com/artinZareie/hina_notes/backend/internal/models"

	"gorm.io/gorm"
)

const verificationTokenTTL = 24 * time.Hour

var (
	ErrInvalidVerificationToken = errors.New("invalid or expired verification token")
	ErrEmailAlreadyVerified     = errors.New("email is already verified")
)

func generateVerificationToken() (rawToken string, tokenHash string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	rawToken = base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(rawToken))
	tokenHash = hex.EncodeToString(sum[:])
	return rawToken, tokenHash, nil
}

func hashVerificationToken(rawToken string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(rawToken)))
	return hex.EncodeToString(sum[:])
}

func (s *UserService) SendVerificationEmail(ctx context.Context, userID uint, verifyBaseURL string, mailer *mail.Mailer) error {
	if mailer == nil {
		return errors.New("mailer is not configured")
	}

	user, err := s.GetByID(ctx, userID)
	if err != nil {
		return err
	}
	if user.EmailVerifiedAt != nil {
		return ErrEmailAlreadyVerified
	}

	rawToken, tokenHash, err := generateVerificationToken()
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	record := &models.EmailVerificationToken{
		UserID:    user.ID,
		TokenHash: tokenHash,
		ExpiresAt: now.Add(verificationTokenTTL),
	}

	err = s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("user_id = ? AND used_at IS NULL", user.ID).
			Delete(&models.EmailVerificationToken{}).Error; err != nil {
			return err
		}
		return tx.Create(record).Error
	})
	if err != nil {
		return err
	}

	sep := "?"
	if strings.Contains(verifyBaseURL, "?") {
		sep = "&"
	}
	link := fmt.Sprintf("%s%stoken=%s", verifyBaseURL, sep, rawToken)

	return mailer.Send(user.Email, mailables.VerifyEmail{
		Name: user.Name,
		Link: link,
	})
}

func (s *UserService) VerifyEmail(ctx context.Context, rawToken string) (*models.User, error) {
	trimmed := strings.TrimSpace(rawToken)
	if trimmed == "" {
		return nil, ErrInvalidVerificationToken
	}

	tokenHash := hashVerificationToken(trimmed)
	now := time.Now().UTC()

	var verifiedUser models.User
	err := s.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		var tok models.EmailVerificationToken
		err := tx.Where("token_hash = ? AND used_at IS NULL AND expires_at > ?", tokenHash, now).
			First(&tok).Error
		if err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrInvalidVerificationToken
			}
			return err
		}

		res := tx.Model(&models.EmailVerificationToken{}).
			Where("id = ? AND used_at IS NULL", tok.ID).
			Update("used_at", &now)
		if res.Error != nil {
			return res.Error
		}
		if res.RowsAffected == 0 {
			return ErrInvalidVerificationToken
		}

		if err := tx.Model(&models.User{}).
			Where("id = ?", tok.UserID).
			Update("email_verified_at", &now).Error; err != nil {
			return err
		}

		return tx.First(&verifiedUser, tok.UserID).Error
	})
	if err != nil {
		return nil, err
	}

	return &verifiedUser, nil
}

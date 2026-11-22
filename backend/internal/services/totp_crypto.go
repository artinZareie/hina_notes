package services

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

const (
	recoveryCodeCount    = 4
	recoveryCodeBytes    = 5 // 5 random bytes -> 10 hex/base32 chars, formatted e.g. ABCD-EFGH-IJ
	pendingTOTPSecretKey = "pending_totp_secret"
	pending2FAUserKey    = "pending_2fa_user_id"
	twoFAVerifiedAtKey   = "2fa_verified_at"
)

var ErrInvalidEncryptionKey = errors.New("totp encryption key must decode to 32 bytes")

func ParseAES256Key(raw string) ([]byte, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, ErrInvalidEncryptionKey
	}

	if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil && len(decoded) == 32 {
		return decoded, nil
	}
	if decoded, err := hex.DecodeString(trimmed); err == nil && len(decoded) == 32 {
		return decoded, nil
	}

	return nil, ErrInvalidEncryptionKey
}

func EncryptSecret(key []byte, plaintext string) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

func DecryptSecret(key []byte, encoded string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(raw) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertext := raw[:nonceSize], raw[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func GenerateRecoveryCodes(count int) (plainCodes []string, hashedCodes []string, err error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // avoids 0/O/1/I ambiguity
	plainCodes = make([]string, 0, count)
	hashedCodes = make([]string, 0, count)

	for i := 0; i < count; i++ {
		buf := make([]byte, 8)
		if _, err := io.ReadFull(rand.Reader, buf); err != nil {
			return nil, nil, err
		}

		var sb strings.Builder
		for idx, b := range buf {
			if idx == 4 {
				sb.WriteByte('-')
			}
			sb.WriteByte(alphabet[int(b)%len(alphabet)])
		}
		plain := sb.String()

		hash, err := bcrypt.GenerateFromPassword([]byte(NormalizeRecoveryCode(plain)), bcrypt.DefaultCost)
		if err != nil {
			return nil, nil, err
		}

		plainCodes = append(plainCodes, plain)
		hashedCodes = append(hashedCodes, string(hash))
	}

	return plainCodes, hashedCodes, nil
}

func NormalizeRecoveryCode(code string) string {
	s := strings.ToUpper(strings.TrimSpace(code))
	s = strings.ReplaceAll(s, "-", "")
	s = strings.ReplaceAll(s, " ", "")
	if len(s) == 8 {
		return fmt.Sprintf("%s-%s", s[:4], s[4:])
	}
	return s
}

func validateTOTPWithSkew(code string, secret string, skew uint) bool {
	valid, err := totp.ValidateCustom(
		strings.TrimSpace(code),
		secret,
		time.Now().UTC(),
		totp.ValidateOpts{
			Period:    30,
			Skew:      skew,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		},
	)
	return err == nil && valid
}

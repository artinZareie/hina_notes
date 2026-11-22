package middlewares

import (
	"context"
	"net/http"
	"time"

	"github.com/artinZareie/hina_notes/backend/internal/models"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
)

const (
	SessionUserIDKey   = "user_id"
	TwoFAVerifiedAtKey = "2fa_verified_at"
	ContextUserKey     = "current_user"
)

type UserLoader interface {
	GetByID(ctx context.Context, id uint) (*models.User, error)
}

type TwoFAVerifier interface {
	VerifyTOTPOrRecovery(ctx context.Context, userID uint, code string) error
}

type AuthMiddleware struct {
	users    UserLoader
	verifier TwoFAVerifier
}

func NewAuthMiddleware(users UserLoader, verifier TwoFAVerifier) *AuthMiddleware {
	return &AuthMiddleware{users: users, verifier: verifier}
}

func (m *AuthMiddleware) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		userID, ok := toUint(session.Get(SessionUserIDKey))
		if !ok || userID == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		user, err := m.users.GetByID(c.Request.Context(), userID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		c.Set(SessionUserIDKey, user.ID)
		c.Set(ContextUserKey, user)
		c.Next()
	}
}

func (m *AuthMiddleware) Require2FA(maxAge time.Duration) gin.HandlerFunc {
	if maxAge <= 0 {
		maxAge = 10 * time.Minute
	}

	return func(c *gin.Context) {
		user, ok := CurrentUser(c)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}

		if !user.TOTPEnabled {
			c.Next()
			return
		}

		session := sessions.Default(c)
		verifiedUnix, ok := toInt64(session.Get(TwoFAVerifiedAtKey))
		if ok && verifiedUnix > 0 && time.Since(time.Unix(verifiedUnix, 0)) <= maxAge {
			c.Next()
			return
		}

		code := c.GetHeader("X-2FA-Code")
		if code == "" || m.verifier == nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "2fa verification required"})
			return
		}

		if err := m.verifier.VerifyTOTPOrRecovery(c.Request.Context(), user.ID, code); err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid two-factor or recovery code"})
			return
		}

		session.Set(TwoFAVerifiedAtKey, time.Now().UTC().Unix())
		if err := session.Save(); err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to update session"})
			return
		}

		c.Next()
	}
}

func CurrentUser(c *gin.Context) (*models.User, bool) {
	val, exists := c.Get(ContextUserKey)
	if !exists {
		return nil, false
	}
	user, ok := val.(*models.User)
	return user, ok && user != nil
}

func toUint(v any) (uint, bool) {
	switch id := v.(type) {
	case uint:
		return id, true
	case int:
		if id < 0 {
			return 0, false
		}
		return uint(id), true
	case int64:
		if id < 0 {
			return 0, false
		}
		return uint(id), true
	case float64:
		if id < 0 {
			return 0, false
		}
		return uint(id), true
	default:
		return 0, false
	}
}

func toInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int64:
		return n, true
	case int:
		return int64(n), true
	case uint:
		return int64(n), true
	case float64:
		return int64(n), true
	default:
		return 0, false
	}
}

package controllers

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/artinZareie/hina_notes/backend/internal/config"
	"github.com/artinZareie/hina_notes/backend/internal/dto"
	"github.com/artinZareie/hina_notes/backend/internal/mail"
	"github.com/artinZareie/hina_notes/backend/internal/middlewares"
	"github.com/artinZareie/hina_notes/backend/internal/models"
	"github.com/artinZareie/hina_notes/backend/internal/services"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/oaswrap/ginopenapi"
	"github.com/oaswrap/spec/option"
)

const (
	sessionUserIDKey     = "user_id"
	pending2FAUserIDKey  = "pending_2fa_user_id"
	pendingTOTPSecretKey = "pending_totp_secret"
)

type UserController struct {
	cfg           *config.Config
	svc           *services.UserService
	mailer        *mail.Mailer
	verifyBaseURL string
}

func NewUserController(svc *services.UserService, mailer *mail.Mailer, cfg *config.Config) *UserController {
	base := strings.TrimRight(cfg.ServerArgs.BaseUrl, "/")
	if cfg.ServerArgs.Port != "" && !strings.Contains(strings.TrimPrefix(strings.TrimPrefix(base, "http://"), "https://"), ":") {
		base = fmt.Sprintf("%s:%s", base, cfg.ServerArgs.Port)
	}

	verifyBaseURL := fmt.Sprintf("%s/api/v1/users/verify_email", base)

	return &UserController{
		svc:           svc,
		mailer:        mailer,
		verifyBaseURL: verifyBaseURL,
	}
}

func (h *UserController) RegisterRoutes(rg ginopenapi.Router, authMW *middlewares.AuthMiddleware) {
	users := rg.Group("/users")
	auth := users.Group("/auth")

	auth.POST("/register", h.Register).With(
		option.Summary("Register a new user"),
		option.Request(new(dto.RegisterRequest)),
		option.Response(http.StatusCreated, new(dto.UserResponse)),
		option.Response(http.StatusBadRequest, new(dto.ErrorResponse)),
		option.Response(http.StatusConflict, new(dto.ErrorResponse)),
	)

	auth.POST("/login", h.Login).With(
		option.Summary("Log in with email and password"),
		option.Request(new(dto.LoginRequest)),
		option.Response(http.StatusOK, new(dto.UserResponse)),
		option.Response(http.StatusBadRequest, new(dto.ErrorResponse)),
		option.Response(http.StatusUnauthorized, new(dto.ErrorResponse)),
	)

	auth.POST("/logout", h.Logout).With(
		option.Summary("Log out current session"),
		option.Security("cookieAuth"),
		option.Request(new(dto.ProtectedActionRequest)),
		option.Response(http.StatusOK, new(dto.MessageResponse)),
	)

	users.GET("/me", authMW.RequireAuth(), h.Me).With(
		option.Summary("Get current user"),
		option.Security("cookieAuth"),
		option.Response(http.StatusOK, new(dto.UserResponse)),
		option.Response(http.StatusUnauthorized, new(dto.ErrorResponse)),
	)

	users.PATCH("/me", authMW.RequireAuth(), h.UpdateProfile).With(
		option.Summary("Update user profile"),
		option.Security("cookieAuth"),
		option.Request(new(dto.UpdateProfileRequest)), // embed dto.CSRFHeader
		option.Response(http.StatusOK, new(dto.UserResponse)),
		option.Response(http.StatusBadRequest, new(dto.ErrorResponse)),
		option.Response(http.StatusUnauthorized, new(dto.ErrorResponse)),
	)

	users.PUT("/me/password", authMW.RequireAuth(), authMW.Require2FA(10*time.Minute), h.ChangePassword).With(
		option.Summary("Change password"),
		option.Security("cookieAuth"),
		option.Request(new(dto.ChangePasswordRequest)),
		option.Response(http.StatusOK, new(dto.MessageResponse)),
		option.Response(http.StatusBadRequest, new(dto.ErrorResponse)),
		option.Response(http.StatusUnauthorized, new(dto.ErrorResponse)),
	)

	users.DELETE("/me", authMW.RequireAuth(), authMW.Require2FA(0), h.DeleteMe).With(
		option.Summary("Delete account"),
		option.Security("cookieAuth"),
		option.Request(new(dto.ProtectedActionRequest)),
		option.Response(http.StatusOK, new(dto.MessageResponse)),
		option.Response(http.StatusUnauthorized, new(dto.ErrorResponse)),
	)

	users.GET("/verify_email", h.VerifyEmailGet).With(
		option.Summary("Verify email via query token"),
		option.Request(new(dto.VerifyEmailQuery)),
		option.Response(http.StatusOK, new(dto.MessageResponse)),
		option.Response(http.StatusBadRequest, new(dto.ErrorResponse)),
	)

	users.POST("/verify_email", authMW.RequireAuth(), h.RequestNewVerificationEmail).With(
		option.Summary("Resend verification email"),
		option.Security("cookieAuth"),
		option.Request(new(dto.ProtectedActionRequest)),
		option.Response(http.StatusOK, new(dto.MessageResponse)),
		option.Response(http.StatusConflict, new(dto.ErrorResponse)),
		option.Response(http.StatusUnauthorized, new(dto.ErrorResponse)),
	)

	auth.POST("/email/verify", h.VerifyEmailPost).With(
		option.Summary("Verify email via JSON payload"),
		option.Request(new(dto.VerifyEmailRequest)),
		option.Response(http.StatusOK, new(dto.MessageResponse)),
		option.Response(http.StatusBadRequest, new(dto.ErrorResponse)),
	)

	auth.POST("/2fa/setup", authMW.RequireAuth(), h.Setup2FA).With(
		option.Summary("Initialize TOTP 2FA setup"),
		option.Security("cookieAuth"),
		option.Request(new(dto.ProtectedActionRequest)),
		option.Response(http.StatusOK, new(dto.TOTPSetupResponse)),
		option.Response(http.StatusConflict, new(dto.ErrorResponse)),
		option.Response(http.StatusUnauthorized, new(dto.ErrorResponse)),
	)

	auth.POST("/2fa/enable", authMW.RequireAuth(), h.Enable2FA).With(
		option.Summary("Enable TOTP 2FA"),
		option.Security("cookieAuth"),
		option.Request(new(dto.TOTPEnableRequest)), // embed dto.CSRFHeader
		option.Response(http.StatusOK, new(dto.TOTPEnableResponse)),
		option.Response(http.StatusBadRequest, new(dto.ErrorResponse)),
		option.Response(http.StatusUnauthorized, new(dto.ErrorResponse)),
	)

	auth.POST("/2fa/verify", h.Verify2FA).With(
		option.Summary("Verify TOTP or recovery code"),
		option.Request(new(dto.TOTPVerifyRequest)), // embed dto.CSRFHeader
		option.Response(http.StatusOK, new(dto.UserResponse)),
		option.Response(http.StatusBadRequest, new(dto.ErrorResponse)),
		option.Response(http.StatusUnauthorized, new(dto.ErrorResponse)),
	)

	auth.POST("/2fa/disable", authMW.RequireAuth(), authMW.Require2FA(10*time.Minute), h.Disable2FA).With(
		option.Summary("Disable TOTP 2FA"),
		option.Security("cookieAuth"),
		option.Request(new(dto.ProtectedActionRequest)),
		option.Response(http.StatusOK, new(dto.MessageResponse)),
		option.Response(http.StatusBadRequest, new(dto.ErrorResponse)),
		option.Response(http.StatusUnauthorized, new(dto.ErrorResponse)),
	)
}

func (h *UserController) Register(c *gin.Context) {
	var req dto.RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.svc.Register(c.Request.Context(), req)
	if err != nil {
		if errors.Is(err, services.ErrEmailTaken) {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to register user"})
		return
	}

	verificationSent := true
	if err := h.svc.SendVerificationEmail(c.Request.Context(), user.ID, h.verifyBaseURL, h.mailer); err != nil &&
		!errors.Is(err, services.ErrEmailAlreadyVerified) {
		log.Printf("failed to send verification email to user %d: %v", user.ID, err)
		verificationSent = false
	}

	if err := setAuthenticatedSession(c, user.ID, false); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create session"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"user":                    toUserResponse(user),
		"verification_email_sent": verificationSent,
	})
}

func (h *UserController) RequestNewVerificationEmail(c *gin.Context) {
	user, ok := middlewares.CurrentUser(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	if err := h.svc.SendVerificationEmail(c.Request.Context(), user.ID, h.verifyBaseURL, h.mailer); err != nil {
		if errors.Is(err, services.ErrEmailAlreadyVerified) {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to send verification email"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "verification email sent"})
}

func (h *UserController) VerifyEmailGet(c *gin.Context) {
	h.completeEmailVerification(c, c.Query("token"))
}

func (h *UserController) VerifyEmailPost(c *gin.Context) {
	var req dto.VerifyEmailRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	h.completeEmailVerification(c, req.Token)
}

func (h *UserController) completeEmailVerification(c *gin.Context, rawToken string) {
	user, err := h.svc.VerifyEmail(c.Request.Context(), rawToken)
	if err != nil {
		if errors.Is(err, services.ErrInvalidVerificationToken) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to verify email"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "email verified",
		"user":    toUserResponse(user),
	})
}

func (h *UserController) Login(c *gin.Context) {
	var req dto.LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := h.svc.Login(c.Request.Context(), req)
	if err != nil {
		if errors.Is(err, services.ErrInvalidCredentials) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to log in"})
		return
	}

	if user.TOTPEnabled {
		session := sessions.Default(c)
		session.Clear()
		session.Set(pending2FAUserIDKey, user.ID)
		if err := session.Save(); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to initialize 2fa challenge"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"requires_2fa": true})
		return
	}

	if err := setAuthenticatedSession(c, user.ID, false); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"user": toUserResponse(user)})
}

func (h *UserController) Logout(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	session.Options(sessions.Options{
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})

	if err := session.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to log out"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "logged out"})
}

func (h *UserController) Me(c *gin.Context) {
	user, ok := middlewares.CurrentUser(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"user": toUserResponse(user)})
}

func (h *UserController) Setup2FA(c *gin.Context) {
	user, ok := middlewares.CurrentUser(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	secret, otpauthURL, err := h.svc.SetupTOTP(c.Request.Context(), user.ID)
	if err != nil {
		if errors.Is(err, services.ErrTOTPAlreadyEnabled) {
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to setup 2fa"})
		return
	}

	session := sessions.Default(c)
	session.Set(pendingTOTPSecretKey, secret)
	if err := session.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save 2fa setup state"})
		return
	}

	c.JSON(http.StatusOK, dto.TOTPSetupResponse{
		Secret:     secret,
		OTPAuthURL: otpauthURL,
	})
}

func (h *UserController) Enable2FA(c *gin.Context) {
	user, ok := middlewares.CurrentUser(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req dto.TOTPEnableRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	session := sessions.Default(c)
	pendingSecret, _ := session.Get(pendingTOTPSecretKey).(string)

	codes, err := h.svc.EnableTOTP(c.Request.Context(), user.ID, pendingSecret, req.Code)
	if err != nil {
		switch {
		case errors.Is(err, services.ErrNoPendingTOTP):
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		case errors.Is(err, services.ErrTOTPAlreadyEnabled):
			c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		case errors.Is(err, services.ErrInvalidTOTPCode):
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to enable 2fa"})
		}
		return
	}

	session.Delete(pendingTOTPSecretKey)
	session.Set(middlewares.TwoFAVerifiedAtKey, time.Now().UTC().Unix())
	if err := session.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update session"})
		return
	}

	c.JSON(http.StatusOK, dto.TOTPEnableResponse{
		Message:       "two-factor authentication enabled",
		RecoveryCodes: codes,
	})
}

func (h *UserController) Verify2FA(c *gin.Context) {
	var req dto.TOTPVerifyRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	session := sessions.Default(c)
	var targetUserID uint
	var completingLogin bool

	if pendingID, ok := toUint(session.Get(pending2FAUserIDKey)); ok && pendingID > 0 {
		targetUserID = pendingID
		completingLogin = true
	} else if activeID, ok := toUint(session.Get(middlewares.SessionUserIDKey)); ok && activeID > 0 {
		targetUserID = activeID
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "no active login or session requiring 2fa"})
		return
	}

	if err := h.svc.VerifyTOTPOrRecovery(c.Request.Context(), targetUserID, req.Code); err != nil {
		switch {
		case errors.Is(err, services.ErrTOTPNotEnabled):
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		case errors.Is(err, services.ErrInvalidTOTPCode):
			c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to verify 2fa code"})
		}
		return
	}

	if completingLogin {
		if err := setAuthenticatedSession(c, targetUserID, true); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to complete login session"})
			return
		}
		user, err := h.svc.GetByID(c.Request.Context(), targetUserID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load user"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"user": toUserResponse(user)})
		return
	}

	session.Set(middlewares.TwoFAVerifiedAtKey, time.Now().UTC().Unix())
	if err := session.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"verified": true})
}

func (h *UserController) Disable2FA(c *gin.Context) {
	user, ok := middlewares.CurrentUser(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	if err := h.svc.DisableTOTP(c.Request.Context(), user.ID); err != nil {
		if errors.Is(err, services.ErrTOTPNotEnabled) {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to disable 2fa"})
		return
	}

	session := sessions.Default(c)
	session.Delete(middlewares.TwoFAVerifiedAtKey)
	if err := session.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "two-factor authentication disabled"})
}

func setAuthenticatedSession(c *gin.Context, userID uint, mark2FAVerified bool) error {
	session := sessions.Default(c)
	session.Clear()
	session.Set(middlewares.SessionUserIDKey, userID)
	if mark2FAVerified {
		session.Set(middlewares.TwoFAVerifiedAtKey, time.Now().UTC().Unix())
	}
	return session.Save()
}

func toUserResponse(u *models.User) dto.UserResponse {
	return dto.UserResponse{
		ID:              u.ID,
		Email:           u.Email,
		Name:            u.Name,
		EmailVerifiedAt: u.EmailVerifiedAt,
		TOTPEnabled:     u.TOTPEnabled,
	}
}

func (h *UserController) DeleteMe(c *gin.Context) {
	user, ok := middlewares.CurrentUser(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	if err := h.svc.DeleteUser(c.Request.Context(), user.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete user"})
		return
	}

	session := sessions.Default(c)
	session.Clear()
	session.Options(sessions.Options{
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
	})
	if err := session.Save(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to clear session"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "account deleted"})
}

func (h *UserController) UpdateProfile(c *gin.Context) {
	currentUser, ok := middlewares.CurrentUser(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req dto.UpdateProfileRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updated, err := h.svc.UpdateName(c.Request.Context(), currentUser.ID, req.Name)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"user": toUserResponse(updated)})
}

func (h *UserController) ChangePassword(c *gin.Context) {
	currentUser, ok := middlewares.CurrentUser(c)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	var req dto.ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := h.svc.ChangePassword(c.Request.Context(), currentUser.ID, req.CurrentPassword, req.NewPassword); err != nil {
		switch {
		case errors.Is(err, services.ErrInvalidCredentials):
			c.JSON(http.StatusUnauthorized, gin.H{"error": "current password is incorrect"})
		case errors.Is(err, services.ErrSamePassword):
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update password"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "password updated"})
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

package controllers

import (
	"context"
	"errors"
	"net/http"

	"github.com/artinZareie/hina_notes/backend/internal/dto"
	"github.com/artinZareie/hina_notes/backend/internal/models"
	"github.com/artinZareie/hina_notes/backend/internal/services"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/oaswrap/ginopenapi"
)

const sessionUserIDKey = "user_id"

type UserService interface {
	SayHello(ctx context.Context) (string, error)
	Register(ctx context.Context, req dto.RegisterRequest) (*models.User, error)
	Login(ctx context.Context, req dto.LoginRequest) (*models.User, error)
	GetByID(ctx context.Context, id uint) (*models.User, error)
}

type UserController struct {
	svc UserService
}

func NewUserController(svc UserService) *UserController {
	return &UserController{svc: svc}
}

func (h *UserController) RegisterRoutes(rg ginopenapi.Router) {
	users := rg.Group("/users")

	auth := users.Group("/auth")
	auth.POST("/register", h.Register)
	auth.POST("/login", h.Login)
	auth.POST("/logout", h.Logout)
	auth.GET("/me", h.RequireAuth(), h.Me)
}

func (h *UserController) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		rawID := session.Get(sessionUserIDKey)
		userID, ok := toUint(rawID)
		if !ok || userID == 0 {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return
		}
		c.Set(sessionUserIDKey, userID)
		c.Next()
	}
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

	if err := setSessionUserID(c, user.ID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create session"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"user": toUserResponse(user)})
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

	if err := setSessionUserID(c, user.ID); err != nil {
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
	rawID, exists := c.Get(sessionUserIDKey)
	userID, ok := toUint(rawID)
	if !exists || !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return
	}

	user, err := h.svc.GetByID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"user": toUserResponse(user)})
}

func setSessionUserID(c *gin.Context, userID uint) error {
	session := sessions.Default(c)
	session.Clear()
	session.Set(sessionUserIDKey, userID)
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

package controllers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/oaswrap/ginopenapi"
)

type UserService interface {
	SayHello(ctx context.Context) (string, error)
}

type UserController struct {
	svc UserService
}

func NewUserController(svc UserService) *UserController {
	return &UserController{svc: svc}
}

func (h *UserController) RegisterRoutes(rg ginopenapi.Router) {
	users := rg.Group("/users")

	users.GET("", h.SayHello)
}

func (h *UserController) SayHello(c *gin.Context) {
	msg, err := h.svc.SayHello(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": msg})
}

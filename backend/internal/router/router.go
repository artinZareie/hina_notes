package router

import (
	"github.com/artinZareie/hina_notes/backend/internal/config"
	"github.com/artinZareie/hina_notes/backend/internal/controllers"
	"github.com/artinZareie/hina_notes/backend/internal/services"

	"github.com/gin-gonic/gin"
)

func New(cfg *config.Config, r *gin.Engine) *gin.Engine {
	api := r.Group("/api")
	{
		v1 := api.Group("v1")

		{
			userSvc := services.NewUserService()
			userCtrl := controllers.NewUserController(userSvc)

			userCtrl.RegisterRoutes(v1)
		}
	}

	return r
}

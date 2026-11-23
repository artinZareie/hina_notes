package router

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"

	"github.com/artinZareie/hina_notes/backend/internal/config"
	"github.com/artinZareie/hina_notes/backend/internal/controllers"
	"github.com/artinZareie/hina_notes/backend/internal/mail"
	"github.com/artinZareie/hina_notes/backend/internal/middlewares"
	"github.com/artinZareie/hina_notes/backend/internal/services"

	csrf "github.com/utrack/gin-csrf"
	"gorm.io/gorm"

	"github.com/gin-gonic/gin"
	"github.com/oaswrap/ginopenapi"
	"github.com/oaswrap/spec/option"
	"github.com/watchakorn-18k/scalar-go"
	scalargin "github.com/watchakorn-18k/scalar-go/middleware/gin"
)

func New(cfg *config.Config, r *gin.Engine, db *gorm.DB) (*gin.Engine, error) {
	router := ginopenapi.NewRouter(
		r,
		option.WithTitle("hina_notes API"),
		option.WithVersion("1.0.0"),
		option.WithDescription("Hina Notes backend API"),
		option.WithOpenAPIVersion("3.0.3"),
	)

	api := router.Group("/api")
	{
		v1 := api.Group("/v1")

		v1.GET("/csrf-token", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"csrf_token": csrf.GetToken(c),
			})
		})

		{
			userSvc, err := services.NewUserService(db, cfg.TOTPEncryptionKey)
			if err != nil {
				return nil, fmt.Errorf("invalid totp key: %w", err)
			}

			authMW := middlewares.NewAuthMiddleware(userSvc, userSvc)
			mailer, err := mail.NewMailer(cfg.MailArgs)
			if err != nil {
				return nil, fmt.Errorf("init mailer: %w", err)
			}

			userCtrl := controllers.NewUserController(userSvc, mailer, cfg)
			userCtrl.RegisterRoutes(v1, authMW)
		}
	}

	const specFile = "openapi.json"
	if err := os.MkdirAll("docs", 0o755); err != nil {
		return nil, fmt.Errorf("create docs dir: %w", err)
	}
	if err := router.WriteSchemaTo(filepath.Join("docs", specFile)); err != nil {
		return nil, fmt.Errorf("write %s: %w", specFile, err)
	}

	RegisterDocsRoutes(r)

	return r, nil
}

func RegisterDocsRoutes(r *gin.Engine) {
	r.GET("/scalar", scalargin.Handler(&scalar.Options{
		SpecURL:      "/docs/openapi.yaml",
		ValidateSpec: true,
		PageTitle:    "API Reference",
	}))
}

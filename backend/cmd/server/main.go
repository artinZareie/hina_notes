package main

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/artinZareie/hina_notes/backend/internal/config"
	"github.com/artinZareie/hina_notes/backend/internal/database"
	"github.com/artinZareie/hina_notes/backend/internal/router"
	"github.com/gin-gonic/gin"

	"github.com/gin-contrib/cors"
	"github.com/joho/godotenv"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/redis"
	"github.com/utrack/gin-csrf"
)

func main() {
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found.")
	}

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("Could not read env variables: %v", err)
	}

	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=hina_notes port=5432 sslmode=disable",
		cfg.DatabaseArgs.DbUrl,
		cfg.DatabaseArgs.User,
		cfg.DatabaseArgs.Password,
	)

	db, err := database.Connect(dsn)
	if err != nil {
		log.Fatalf("Database connection failed: %v", err)
	}
	defer func() {
		if sqlDB, err := db.DB(); err == nil {
			_ = sqlDB.Close()
		}
	}()

	err = database.AutoMigrate(db)
	if err != nil {
		log.Fatalf("%v", err)
	}

	if cfg.Mode == config.ProductionLaunchMode {
		gin.SetMode(gin.ReleaseMode)
	}

	r := gin.Default()

	if cfg.Mode == config.ProductionLaunchMode {
		_ = r.SetTrustedProxies(nil)
	}

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{cfg.FrontendUrl},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization", "X-CSRF-Token"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))

	store, err := redis.NewStore(
		10,
		"tcp",
		cfg.RedisArgs.Addr,
		cfg.RedisArgs.Username,
		cfg.RedisArgs.Password,
		[]byte(cfg.RedisArgs.Secret),
	)
	if err != nil {
		log.Fatalf("Failed to start Redis: %v", err)
	}

	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   86400 * 7,                               // 7 days
		HttpOnly: true,                                    // JavaScript cannot read it
		Secure:   cfg.Mode == config.ProductionLaunchMode, // HTTPS only in prod
		SameSite: http.SameSiteLaxMode,
	})

	r.Use(sessions.Sessions("hina_session", store))

	r.Use(csrf.Middleware(csrf.Options{
		Secret: cfg.RedisArgs.Secret,
		ErrorFunc: func(c *gin.Context) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "csrf token mismatch"})
		},
	}))

	router.New(&cfg, r, db)

	log.Println("Starting the server...")

	if err := r.Run(":" + cfg.ServerArgs.Port); err != nil {
		log.Fatalf("server: %v", err)
	}
}

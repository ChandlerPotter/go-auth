package main

import (
	"log"
	"os"

	_ "go-auth/config"
	"go-auth/database"
	handlers "go-auth/internal/handlers/auth"
	"go-auth/internal/middleware"
	"go-auth/internal/stores"
	"go-auth/internal/token"
	"go-auth/internal/user"

	"github.com/gin-gonic/gin"
)

func main() {
	db, err := database.ConnectDB()
	if err != nil {
		log.Fatalf("Database connection error: %v", err)
	}

	// 2) Run migrations
	database.ProcessMigrations(db)

	userStore := &stores.GormUserStore{DB: db}
	secret := []byte(os.Getenv("JWT_SECRET"))
	hasher := user.BcryptHasher{}
	tokenService := &token.JWTService{Secret: secret}

	refreshTokenStore := &stores.GormRefreshTokenStore{
		DB:           db,
		TokenService: tokenService,
	}

	auth := handlers.NewAuthHandler(
		userStore,
		refreshTokenStore,
		secret,
		hasher,
		tokenService)

	// Initialize router
	r := gin.Default()

	// Public route to register user
	authGroup := r.Group("/auth")
	{
		authGroup.POST("/register", auth.Register)
		authGroup.POST("/login", auth.Login)
		authGroup.POST("/refresh", auth.RefreshToken)
	}

	// Register a protected route
	protected := r.Group("/")
	protected.Use(middleware.JWTAuthMiddleware())
	{
		protected.GET("/me", auth.GetCurrentUser)
	}

	// Example: test route
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(200, gin.H{"message": "pong"})
	})

	// Start server on port from env or fallback
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	r.Run(":" + port)
}

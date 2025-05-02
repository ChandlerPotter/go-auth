package main

import (
	"log"
	"os"

	_ "go-auth/config"
	"go-auth/database"
	handlers "go-auth/handlers/auth"
	"go-auth/middleware"
	"go-auth/stores"

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
	hasher := handlers.BcryptHasher{}
	tokenService := &handlers.JWTService{
		Secret: secret,
	}

	auth := handlers.NewAuthHandler(userStore, secret, hasher, tokenService)

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
		protected.GET("/me", handlers.GetCurrentUser)
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

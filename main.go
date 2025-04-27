package main

import (
	"os"

	_ "go-auth/config"
	"go-auth/database"
	"go-auth/handlers"
	"go-auth/middleware"

	"github.com/gin-gonic/gin"
)

func main() {
	database.ConnectDB()

	// Perform migrations
	database.ProcessMigrations()

	// Initialize router
	r := gin.Default()

	// Public route to register user
	auth := r.Group("/auth")
	{
		auth.POST("/register", handlers.Register)
		auth.POST("/login", handlers.Login)
		auth.POST("/refresh", handlers.RefreshToken)
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

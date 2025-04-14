package main

import (
	"os"

	"like-hub/database"
	"like-hub/handlers"

	"github.com/gin-gonic/gin"
)

func main() {
	database.ConnectDB()

	// Perform migrations
	database.ProcessMigrations()

	// Initialize router
	r := gin.Default()

	// Public route to register user
	r.POST("/register", handlers.Register)

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

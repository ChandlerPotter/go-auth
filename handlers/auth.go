package handlers

import (
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"

	"go-auth/database"
	"go-auth/models"
	"go-auth/utils"
)

type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	RoleID   uint   `json:"roleId"   binding:"required"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type RefreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

func Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 1. Check if user exists
	var existing models.User

	// validate username length
	if len(req.Username) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username is less than eight characters."})
		return
	}

	if err := database.DB.Where("username = ?", req.Username).First(&existing).Error; err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Username already taken"})
		return
	}

	// 2. Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error hashing password"})
		return
	}

	// 3. Create the user record
	user := models.User{
		Username:     req.Username,
		PasswordHash: string(hashedPassword),
		RoleID:       req.RoleID,
	}

	if err := database.DB.Create(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "user registered successfully"})
}

func Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	// Find user by username
	var user models.User
	if err := database.DB.Preload("Role").Where("username = ?", req.Username).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
		return
	}

	// Compare password hash
	err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
		return
	}

	// Sign the token
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Println("⚠️ JWT_SECRET not set in env")
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server configuration error"})
		return
	}

	// Create JWT token
	tokenString, err := utils.GenerateAccessToken(user.ID, user.Role.Name, 30*time.Minute, []byte(secret))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not sign token"})
		return
	}

	// Generate a refresh token
	refreshTokenString, hashedTokenString, err := utils.GenerateRandomRefreshToken(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate refresh token string"})
		return
	}

	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	refreshToken := models.RefreshToken{
		TokenHash: hashedTokenString, // Store hashed token
		UserID:    user.ID,
		ExpiresAt: expiresAt,
	}

	if err := database.DB.Create(&refreshToken).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not save refresh token to database"})
		return
	}

	// Respond with the token
	c.JSON(http.StatusOK, gin.H{
		"token":         tokenString,
		"refresh_token": refreshTokenString,
	})
}

func GetCurrentUser(c *gin.Context) {
	userIDVal, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found in context"})
		return
	}

	userID := userIDVal.(uint)

	var user models.User
	if err := database.DB.Preload("Role").First(&user, userID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":       user.ID,
		"username": user.Username,
		"role":     user.Role.Name,
	})
}

func RefreshToken(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	var refreshToken models.RefreshToken
	if err := database.DB.Where("token = ?", req.RefreshToken).First(&refreshToken).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}

	if time.Now().After(refreshToken.ExpiresAt) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "refresh token expired"})
		return
	}

	var user models.User
	if err := database.DB.Preload("Role").First(&user, refreshToken.UserID).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "user not found"})
		return
	}

	// Sign the token
	secret := os.Getenv("JWT_SECRET")

	// Create JWT token
	tokenString, err := utils.GenerateAccessToken(user.ID, user.Role.Name, 30*time.Minute, []byte(secret))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not sign token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": tokenString,
	})
}

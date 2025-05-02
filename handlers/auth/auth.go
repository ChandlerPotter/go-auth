package handlers

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"

	"go-auth/database"
	"go-auth/models"
	"go-auth/stores"
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

type PasswordHasher interface {
	Hash(password []byte) ([]byte, error)
	Compare(hash, password []byte) error
}

type TokenService interface {
	GenerateRandomRefreshToken(length int) (raw string, hash []byte, err error)
	HashRefreshToken(raw string) []byte
	GenerateAccessToken(userID uint, role string, ttl time.Duration) (string, error)
}

type AuthHandler struct {
	Store        stores.UserStore
	Secret       []byte
	Hasher       PasswordHasher
	TokenService TokenService
}

// NewAuthHandler constructs an AuthHandler.
func NewAuthHandler(
	store stores.UserStore,
	secret []byte,
	hasher PasswordHasher,
	tokenService TokenService,
) *AuthHandler {
	return &AuthHandler{
		Store:        store,
		Secret:       secret,
		Hasher:       hasher,
		TokenService: tokenService,
	}
}

func (h *AuthHandler) Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// validate username length
	if len(req.Username) < 8 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username is less than eight characters."})
		return
	}

	if _, err := h.Store.FindByUsername(req.Username); err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Username already taken"})
		return
	} else if !errors.Is(err, stores.ErrNotFound) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server error"})
		return
	}

	// 2. Hash the password
	hashedPassword, err := h.Hasher.Hash([]byte(req.Password))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "error hashing password"})
		return
	}

	// 3. Create the user record
	user := &models.User{
		Username:     req.Username,
		PasswordHash: string(hashedPassword),
		RoleID:       req.RoleID,
	}

	if err := h.Store.CreateUser(user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "user registered successfully"})
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	// Find user by username
	var user models.User
	if _, err := h.Store.FindByUsername(req.Username); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
		return
	}

	// Compare password hash
	err := h.Hasher.Compare([]byte(user.PasswordHash), []byte(req.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
		return
	}

	// Create JWT token
	tokenString, err := h.TokenService.GenerateAccessToken(user.ID, user.Role.Name, 30*time.Minute)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not sign token"})
		return
	}

	// Generate a refresh token
	refreshTokenString, hashedRefreshToken, err := h.TokenService.GenerateRandomRefreshToken(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not generate refresh token string"})
		return
	}

	expiresAt := time.Now().Add(7 * 24 * time.Hour)

	refreshToken := models.RefreshToken{
		TokenHash: hashedRefreshToken, // Store hashed token
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

var errInvalidRefresh = errors.New("invalid refresh token")

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	hash := h.TokenService.HashRefreshToken(req.RefreshToken)

	if err := database.DB.Transaction(func(tx *gorm.DB) error {
		var refreshToken models.RefreshToken

		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Preload("User.Role").
			Where("token_hash = ? AND expires_at > ?", hash, time.Now()).
			First(&refreshToken).Error; err != nil {

			return errors.New("invalid refresh token")
		}
		// Rotate Refresh token
		newRaw, newHash, _ := h.TokenService.GenerateRandomRefreshToken(32)

		refreshToken.TokenHash = newHash
		refreshToken.ExpiresAt = time.Now().Add(7 * 24 * time.Hour)

		if err := tx.Save(&refreshToken).Error; err != nil {
			return err
		}

		// Create JWT token
		accessTokenString, err := h.TokenService.GenerateAccessToken(
			refreshToken.User.ID,
			refreshToken.User.Role.Name,
			30*time.Minute)
		if err != nil {
			return err
		}

		c.Set("token", accessTokenString)
		c.Set("refresh_token", newRaw) // plain-text copy for the client
		return nil

	}); err != nil {
		if errors.Is(err, errInvalidRefresh) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		} else {
			log.Printf("refresh-tx error: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "server error"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token":         c.MustGet("token"),
		"refresh_token": c.MustGet("refresh_token"),
	})
}

package handlers

import (
	"errors"

	"net/http"
	"time"

	"github.com/gin-gonic/gin"

	"go-auth/internal/models"
	"go-auth/internal/stores"
	"go-auth/internal/token"
	"go-auth/internal/user"
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

type LogoutRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type AuthHandler struct {
	UserStore         stores.UserStore
	RefreshTokenStore stores.RefreshTokenStore
	Secret            []byte
	Hasher            user.PasswordHasher
	TokenService      token.TokenService
}

const RefreshTokenExpiration time.Duration = 7 * 24 * time.Hour
const AccessTokenExpiration time.Duration = 15 * time.Minute

// NewAuthHandler constructs an AuthHandler.
func NewAuthHandler(
	userStore stores.UserStore,
	refreshTokenStore stores.RefreshTokenStore,
	secret []byte,
	hasher user.PasswordHasher,
	tokenService token.TokenService,
) *AuthHandler {
	return &AuthHandler{
		UserStore:         userStore,
		RefreshTokenStore: refreshTokenStore,
		Secret:            secret,
		Hasher:            hasher,
		TokenService:      tokenService,
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

	if _, err := h.UserStore.FindByUsername(req.Username); err == nil {
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

	if err := h.UserStore.CreateUser(user); err != nil {
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
	//var user models.User
	user, err := h.UserStore.FindByUsername(req.Username)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
		return
	}

	// Compare password hash
	if err := h.Hasher.Compare([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid username or password"})
		return
	}

	// Create JWT token
	tokenString, err := h.TokenService.GenerateAccessToken(user.ID, user.Role.Name, AccessTokenExpiration)
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

	if err := h.RefreshTokenStore.CreateRefreshToken(&refreshToken); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not save refresh token to database"})
		return
	}

	// Respond with the token
	c.JSON(http.StatusOK, gin.H{
		"token":         tokenString,
		"refresh_token": refreshTokenString,
	})
}

func (h *AuthHandler) GetCurrentUser(c *gin.Context) {
	userIDVal, exists := c.Get("user_id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User ID not found in context"})
		return
	}

	userID := userIDVal.(uint)

	user, err := h.UserStore.GetByID(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":       user.ID,
		"username": user.Username,
		"role":     user.Role.Name,
	})
}

func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req RefreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	hash := h.TokenService.HashRefreshToken(req.RefreshToken)

	res, err := h.RefreshTokenStore.Rotate(hash, time.Now(), RefreshTokenExpiration)

	if err != nil {
		if errors.Is(err, stores.ErrInvalidRefresh) {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server error"})
		return
	}

	// Create JWT token
	accessTokenString, _ := h.TokenService.GenerateAccessToken(res.UserID, res.RoleName, AccessTokenExpiration)

	c.Set("token", accessTokenString)
	c.Set("refresh_token", res.NewRaw)

	c.JSON(http.StatusOK, gin.H{
		"token":         c.MustGet("token"),
		"refresh_token": c.MustGet("refresh_token"),
	})
}

func (h *AuthHandler) Logout(c *gin.Context) {
	var req LogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	hashed := h.TokenService.HashRefreshToken(req.RefreshToken)

	err := h.RefreshTokenStore.RevokeRefreshToken(hashed)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not revoke refresh token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "logout successful"})
}

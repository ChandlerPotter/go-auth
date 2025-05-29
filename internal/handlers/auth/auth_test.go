package handlers_test

import (
	"bytes"
	"encoding/json"
	handlers "go-auth/internal/handlers/auth"
	"go-auth/internal/mocks"
	"go-auth/internal/models"
	"go-auth/internal/stores"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestRegister(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Arrange
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	body := `{"username":"newuser01","password":"SuperSecret","roleId":2}`
	req, _ := http.NewRequest(http.MethodPost, "/auth/register", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	ctx.Request = req

	userStore := new(mocks.UserStore)
	userStore.On("FindByUsername", "newuser01").Return(nil, stores.ErrNotFound)
	userStore.On("CreateUser", mock.AnythingOfType("*models.User")).Return(nil)

	hasher := new(mocks.PasswordHasher)
	hasher.On("Hash", []byte("SuperSecret")).
		Return([]byte("hashedPW"), nil)

	h := handlers.NewAuthHandler(userStore, nil, nil, hasher, nil)

	// Act
	h.Register(ctx)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "user registered successfully", resp["message"])

	userStore.AssertExpectations(t)
}

func TestLogin(t *testing.T) {
	gin.SetMode(gin.TestMode)

	// Arrange
	w := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(w)

	body := `{"username":"username","password":"correctPW"}`
	req, _ := http.NewRequest(http.MethodPost, "/auth/login", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	ctx.Request = req

	userStore := new(mocks.UserStore)
	userStore.On("FindByUsername", "username").
		Return(&models.User{
			ID:           1,
			Username:     "username",
			PasswordHash: "hashedPW",
			Role:         models.Role{ID: 2, Name: "user"},
		}, nil)

	hm := new(mocks.PasswordHasher)
	hm.On("Compare", []byte("hashedPW"), []byte("correctPW")).Return(nil)

	ts := new(mocks.TokenService)
	ts.On("GenerateAccessToken", uint(1), "user", handlers.AccessTokenExpiration).
		Return("ACCESS_TOKEN", nil)
	ts.On("GenerateRandomRefreshToken", 32).
		Return("REFRESH_TOKEN", []byte{1, 2, 3}, nil)

	// 4) Refresh-token store mock – insert succeeds
	rs := new(mocks.RefreshTokenStore)
	rs.On("CreateRefreshToken", mock.AnythingOfType("*models.RefreshToken")).Return(nil)

	h := handlers.NewAuthHandler(userStore, rs, nil, hm, ts)

	h.Login(ctx)

	// Assert
	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)

	assert.Equal(t, "ACCESS_TOKEN", resp["token"])
	assert.Equal(t, "REFRESH_TOKEN", resp["refresh_token"])

	userStore.AssertExpectations(t)
	hm.AssertExpectations(t)
	ts.AssertExpectations(t)
	rs.AssertExpectations(t)

}

package handlers_test

import (
	"bytes"
	"encoding/json"
	handlers "go-auth/internal/handlers/auth"
	"go-auth/internal/mocks"
	"go-auth/internal/stores"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type stubHasher struct{}

func (stubHasher) Hash(p []byte) ([]byte, error) { return []byte("hashed-" + string(p)), nil }
func (stubHasher) Compare(_, _ []byte) error     { return nil }

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

	h := handlers.NewAuthHandler(
		userStore,
		nil,
		nil,
		stubHasher{},
		nil,
	)

	// Act
	h.Register(ctx)

	// Assert
	assert.Equal(t, http.StatusOK, w.Code)
	var resp map[string]string
	_ = json.Unmarshal(w.Body.Bytes(), &resp)
	assert.Equal(t, "user registered successfully", resp["message"])

	userStore.AssertExpectations(t)
}

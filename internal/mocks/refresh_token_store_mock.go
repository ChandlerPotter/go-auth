package mocks

import (
	"go-auth/internal/models"
	"go-auth/internal/stores"
	"time"

	"github.com/stretchr/testify/mock"
)

type RefreshTokenStore struct{ mock.Mock }

func (m *RefreshTokenStore) CreateRefreshToken(rt *models.RefreshToken) error {
	return m.Called(rt).Error(0)
}

func (m *RefreshTokenStore) Rotate(hash []byte, now time.Time, ttl time.Duration) (stores.RotateResult, error) {
	args := m.Called(hash, now, ttl)
	var out stores.RotateResult
	if v := args.Get(0); v != nil {
		out = v.(stores.RotateResult)
	}
	return out, args.Error(1)
}

func (m *RefreshTokenStore) RevokeRefreshToken(tokenHash []byte) error {
	args := m.Called(tokenHash)
	return args.Error(0)
}

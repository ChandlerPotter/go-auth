package mocks

import (
	"time"

	"github.com/stretchr/testify/mock"
)

type TokenService struct{ mock.Mock }

func (m *TokenService) GenerateRandomRefreshToken(length int) (raw string, hash []byte, err error) {
	args := m.Called(length)
	return args.String(0), args.Get(1).([]byte), args.Error(2)
}

func (m *TokenService) GenerateAccessToken(userID uint, role string, ttl time.Duration) (string, error) {
	args := m.Called(userID, role, ttl)
	return args.String(0), args.Error(1)
}

func (m *TokenService) HashRefreshToken(_ string) []byte { return nil }

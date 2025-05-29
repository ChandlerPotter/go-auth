package token

import "time"

type TokenService interface {
	GenerateRandomRefreshToken(length int) (raw string, hash []byte, err error)
	HashRefreshToken(raw string) []byte
	GenerateAccessToken(userID uint, role string, ttl time.Duration) (string, error)
}

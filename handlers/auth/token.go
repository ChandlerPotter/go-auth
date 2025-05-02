package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type JWTService struct {
	Secret []byte
}

func (s *JWTService) GenerateRandomRefreshToken(length int) (raw string, hash []byte, err error) {
	bytes := make([]byte, length)
	if _, err = rand.Read(bytes); err != nil {
		return
	}

	raw = base64.URLEncoding.EncodeToString(bytes) // what the client sees
	sum := sha256.Sum256([]byte(raw))
	hash = sum[:] // 32-byte slice

	return // <- naked return is fine; named vars carry the values
}

func (s *JWTService) HashRefreshToken(raw string) []byte {
	h := sha256.Sum256([]byte(raw))
	return h[:]
}

type Claims struct {
	UserID uint   `json:"user_id"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

func (s *JWTService) GenerateAccessToken(userID uint, role string, ttl time.Duration) (string, error) {
	now := time.Now()
	claims := Claims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(ttl)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.Secret)
}

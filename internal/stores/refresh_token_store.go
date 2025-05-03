package stores

import (
	"errors"
	"go-auth/internal/models"
	"time"

	"go-auth/internal/token"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type RotateResult struct {
	UserID   uint
	RoleName string
	NewRaw   string
}

type RefreshTokenStore interface {
	CreateRefreshToken(rt *models.RefreshToken) error
	Rotate(hash []byte, now time.Time, ttl time.Duration) (RotateResult, error)
}

// GormUserStore implements UserStore using GORM.
type GormRefreshTokenStore struct {
	DB           *gorm.DB
	TokenService token.TokenService
}

func (s *GormRefreshTokenStore) CreateRefreshToken(rt *models.RefreshToken) error {
	return s.DB.Create(rt).Error
}

func (s *GormRefreshTokenStore) Rotate(hash []byte, now time.Time, ttl time.Duration) (RotateResult, error) {
	var out RotateResult

	err := s.DB.Transaction(func(tx *gorm.DB) error {
		var rt models.RefreshToken
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Preload("User.Role").
			Where("token_hash = ? AND expires_at > ?", hash, now).
			First(&rt).Error; err != nil {

			return errors.New("invalid refresh token")
		}

		// Generate the *next* token
		raw, newHash, err := s.TokenService.GenerateRandomRefreshToken(32)
		if err != nil {
			return err
		}

		// Persist the rotation
		rt.TokenHash = newHash
		rt.ExpiresAt = now.Add(ttl)

		if err := tx.Save(&rt).Error; err != nil {
			return err
		}

		out = RotateResult{
			UserID:   rt.User.ID,
			RoleName: rt.User.Role.Name,
			NewRaw:   raw,
		}
		return nil
	})

	return out, err
}

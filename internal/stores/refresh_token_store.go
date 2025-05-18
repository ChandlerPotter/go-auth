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
	RevokeRefreshToken(tokenHash []byte) error
}

// GormUserStore implements UserStore using GORM.
type GormRefreshTokenStore struct {
	DB           *gorm.DB
	TokenService token.TokenService
}

func (s *GormRefreshTokenStore) CreateRefreshToken(rt *models.RefreshToken) error {
	return s.DB.Create(rt).Error
}

var ErrInvalidRefresh = errors.New("invalid refresh token")

func (s *GormRefreshTokenStore) Rotate(
	hash []byte,
	now time.Time,
	ttl time.Duration,
) (RotateResult, error) {
	var out RotateResult

	err := s.DB.Transaction(func(tx *gorm.DB) error {
		var rt models.RefreshToken
		if err := tx.Clauses(clause.Locking{Strength: "UPDATE"}).
			Preload("User.Role").
			Where("token_hash = ? AND expires_at > ? AND revoked = ?", hash, now, false).
			First(&rt).Error; err != nil {

			return ErrInvalidRefresh
		}

		// Set existing token is revoked
		if err := tx.Model(&rt).Update("revoked", true).Error; err != nil {
			return err
		}

		// Generate the *next* token
		raw, newHash, err := s.TokenService.GenerateRandomRefreshToken(32)
		if err != nil {
			return err
		}

		// Create and persist new token
		newRT := models.RefreshToken{
			TokenHash: newHash,
			UserID:    rt.UserID,
			ExpiresAt: now.Add(ttl),
			Revoked:   false,
		}

		if err := tx.Create(&newRT).Error; err != nil {
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

func (s *GormRefreshTokenStore) RevokeRefreshToken(tokenHash []byte) error {
	return s.DB.Model(&models.RefreshToken{}).
		Where("token_hash = ?", tokenHash).
		Update("revoked", true).Error
}

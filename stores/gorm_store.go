package stores

import (
	"go-auth/models"

	"gorm.io/gorm"
)

var ErrNotFound = gorm.ErrRecordNotFound

// GormUserStore implements UserStore using GORM.
type GormUserStore struct{ DB *gorm.DB }

func (s *GormUserStore) FindByUsername(username string) (*models.User, error) {
	var u models.User
	if err := s.DB.Preload("Role").Where("username = ?", username).First(&u).Error; err != nil {
		return nil, err
	}
	return &u, nil
}

func (s *GormUserStore) CreateUser(u *models.User) error {
	return s.DB.Create(u).Error
}

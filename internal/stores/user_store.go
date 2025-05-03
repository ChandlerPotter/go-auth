package stores

import (
	"go-auth/internal/models"

	"gorm.io/gorm"
)

// UserStore abstracts user persistence.
type UserStore interface {
	// FindByUsername returns a user if it exists, or ErrNotFound.
	FindByUsername(username string) (*models.User, error)
	// CreateUser persists a new user.
	CreateUser(u *models.User) error
	GetByID(id uint) (*models.User, error)
}

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

func (s *GormUserStore) GetByID(id uint) (*models.User, error) {
	var u models.User
	if err := s.DB.Preload("Role").First(&u, id).Error; err != nil {
		return nil, err
	}
	return &u, nil
}

package mocks

import (
	"go-auth/internal/models"

	"github.com/stretchr/testify/mock"
)

type UserStore struct{ mock.Mock }

func (m *UserStore) FindByUsername(u string) (*models.User, error) {
	args := m.Called(u)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*models.User), args.Error(1)
}
func (m *UserStore) CreateUser(u *models.User) error { return m.Called(u).Error(0) }
func (m *UserStore) GetByID(id uint) (*models.User, error) {
	a := m.Called(id)
	return a.Get(0).(*models.User), a.Error(1)
}

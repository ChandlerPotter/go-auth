package mocks

import (
	"github.com/stretchr/testify/mock"
)

type PasswordHasher struct{ mock.Mock }

func (m *PasswordHasher) Hash(p []byte) ([]byte, error) {
	args := m.Called(p)          // <- testify looks for a matching On(...)
	return args.Get(0).([]byte), // []byte result
		args.Error(1) // error result
}

func (m *PasswordHasher) Compare(stored, supplied []byte) error {
	return m.Called(stored, supplied).Error(0)
}

package stores

import "go-auth/models"

// UserStore abstracts user persistence.
type UserStore interface {
	// FindByUsername returns a user if it exists, or ErrNotFound.
	FindByUsername(username string) (*models.User, error)

	// CreateUser persists a new user.
	CreateUser(u *models.User) error
}

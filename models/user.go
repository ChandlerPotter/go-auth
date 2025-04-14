package models

import (
	"time"

	"gorm.io/gorm"
)

// User represents the users table in database.
type User struct {
	// GORM provides a struct called gorm.Model with the fields
	// ID, CreatedAt, UpdatedAt, DeletedAt.
	// You could embed it instead of manually declaring them.
	// For example:
	// gorm.Model
	// That gives you an ID (uint), CreatedAt, UpdatedAt, DeletedAt.

	ID           uint   `gorm:"primaryKey"` // or use gorm.Model
	Username     string `gorm:"unique;not null"`
	PasswordHash string `gorm:"not null"`
	RoleID       uint
	Role         Role `gorm:"foreignKey:RoleID"`
	CreatedAt    time.Time
	UpdatedAt    time.Time
	DeletedAt    gorm.DeletedAt `gorm:"index"` // for soft deletes
}

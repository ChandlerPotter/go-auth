package models

import (
	"time"

	"gorm.io/gorm"
)

const (
	ROLE_ADMIN = 1
	ROLE_USER  = 2
)

type Role struct {
	ID        uint   `gorm:"primaryKey"`
	Name      string `gorm:"unique;not null"`
	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt gorm.DeletedAt `gorm:"index"`
}

package models

import (
	"time"
)

type RefreshToken struct {
	ID        uint   `gorm:"primaryKey"`
	TokenHash string `gorm:"unique;not null"`
	UserID    uint   `gorm:"not null"`
	User      User   `gorm:"foreignKey:UserID"`
	Revoked   bool
	ExpiresAt time.Time
	CreatedAt time.Time
}

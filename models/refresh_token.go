package models

import (
	"time"
)

type RefreshToken struct {
	ID        uint   `gorm:"primaryKey"`
	Token     string `gorm:"unique;not null"`
	UserID    uint   `gorm:"not null"`
	User      User   `gorm:"foreignKey:UserID"`
	ExpiresAt time.Time
	CreatedAt time.Time
}

package database

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"go-auth/internal/models"
)

// DB is a global variable to hold the database connection.
var DB *gorm.DB

// ConnectDB initializes the connection to PostgreSQL using GORM.
func ConnectDB() (*gorm.DB, error) {

	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found or error loading .env file")
	}

	dsn := fmt.Sprintf(
		"host=%s user=%s password=%s dbname=%s port=%s sslmode=%s",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_SSLMODE"),
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to the database: %w", err)
	}

	DB = db
	log.Println("Database connection established")
	return db, nil
}

func ProcessMigrations(db *gorm.DB) {
	err := DB.AutoMigrate(
		&models.User{},
		&models.Role{},
		&models.RefreshToken{})
	if err != nil {
		log.Fatal("Failed to migrate database:", err)
	}

	log.Println("Database migrations complete")

}

package database

import (
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"go-auth/models"
)

// DB is a global variable to hold the database connection.
var DB *gorm.DB

// ConnectDB initializes the connection to PostgreSQL using GORM.
func ConnectDB() {

	err := godotenv.Load()
	if err != nil {
		log.Println("No .env file found or error loading .env file")
		// You can decide if you want this to be a fatal error or not
	}

	host := os.Getenv("DB_HOST")
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	dbname := os.Getenv("DB_NAME")
	port := os.Getenv("DB_PORT")
	sslmode := os.Getenv("DB_SSLMODE") // often "disable" for local dev

	fmt.Printf("Connecting to DB at host=%s user=%s password=%s dbname=%s...\n", host, user, password, dbname)

	// Build DSN (Data Source Name) string
	dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s",
		host, user, password, dbname, port, sslmode,
	)

	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal("Failed to connect to the database: ", err)
	}

	DB = db
	log.Println("Database connection established")
}

func ProcessMigrations() {
	err := DB.AutoMigrate(
		&models.User{},
		&models.Role{})
	if err != nil {
		log.Fatal("Failed to migrate database:", err)
	}

	log.Println("Database migrations complete")

}

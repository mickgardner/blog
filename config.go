package main

import (
	"github.com/joho/godotenv"
	"log"
	"os"
)

type Config struct {
	Env              string
	DBName           string
	Version          string
	Port             string // HTTP server port
	BaseURL          string // Base URL for the application (e.g., https://blog.example.com)
	RedisURL         string
	RedisPort        string
	RedisPassword    string
	RedisDB          string
	EmailService     string // "console", "smtp", "mailgun"
	SMTPHost         string
	SMTPPort         string
	SMTPUsername     string
	SMTPPassword     string
	SMTPFromEmail    string
	SMTPFromName     string
	MailgunDomain    string
	MailgunAPIKey    string
	MailgunFromEmail string
	MailgunFromName  string
	AdminEmail       string
}

func LoadConfig() Config {
	// Use basic logging here since structured logger isn't initialized yet
	log.Println("Loading Configuration...")
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	// Get port with default fallback
	port := os.Getenv("PORT")
	if port == "" {
		port = "3000" // Default port
	}

	baseURL := os.Getenv("BASE_URL")
	if baseURL == "" {
		baseURL = "http://localhost:" + port // Default for development
	}

	config := Config{
		Env:              os.Getenv("ENV"),
		DBName:           os.Getenv("DBNAME"),
		Version:          os.Getenv("VERSION"),
		Port:             port,
		BaseURL:          baseURL,
		RedisURL:         os.Getenv("REDIS_URL"),
		RedisPort:        os.Getenv("REDIS_PORT"),
		RedisPassword:    os.Getenv("REDIS_PASSWORD"),
		RedisDB:          os.Getenv("REDIS_DB"),
		EmailService:     os.Getenv("EMAIL_SERVICE"),
		SMTPHost:         os.Getenv("SMTP_HOST"),
		SMTPPort:         os.Getenv("SMTP_PORT"),
		SMTPUsername:     os.Getenv("SMTP_USERNAME"),
		SMTPPassword:     os.Getenv("SMTP_PASSWORD"),
		SMTPFromEmail:    os.Getenv("SMTP_FROM_EMAIL"),
		SMTPFromName:     os.Getenv("SMTP_FROM_NAME"),
		MailgunDomain:    os.Getenv("MAILGUN_DOMAIN"),
		MailgunAPIKey:    os.Getenv("MAILGUN_API_KEY"),
		MailgunFromEmail: os.Getenv("MAILGUN_FROM_EMAIL"),
		MailgunFromName:  os.Getenv("MAILGUN_FROM_NAME"),
		AdminEmail:       os.Getenv("ADMIN_EMAIL"),
	}
	// Log safe configuration info only (structured logging not yet available)
	log.Printf("Configuration loaded: ENV=%s, VERSION=%s, PORT=%s, EMAIL_SERVICE=%s",
		config.Env, config.Version, config.Port, config.EmailService)
	return config
}

package main

import (
	"os"
	"strings"

	"github.com/sirupsen/logrus"
)

var AppLogger *logrus.Logger

// InitLogger initializes the structured logger
func InitLogger(config Config) {
	AppLogger = logrus.New()

	// Set log level based on environment
	if config.Env == "Development" {
		AppLogger.SetLevel(logrus.DebugLevel)
		AppLogger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp: true,
			ForceColors:   true,
		})
	} else {
		AppLogger.SetLevel(logrus.InfoLevel)
		AppLogger.SetFormatter(&logrus.JSONFormatter{})
	}

	// Set output
	AppLogger.SetOutput(os.Stdout)

	AppLogger.WithFields(logrus.Fields{
		"env":     config.Env,
		"version": config.Version,
	}).Info("Logger initialized")
}

// LogAuth creates a logger for authentication events
func LogAuth() *logrus.Entry {
	return AppLogger.WithField("component", "auth")
}

// LogEmail creates a logger for email events
func LogEmail() *logrus.Entry {
	return AppLogger.WithField("component", "email")
}

// LogArticle creates a logger for article events
func LogArticle() *logrus.Entry {
	return AppLogger.WithField("component", "article")
}

// LogUser creates a logger for user events
func LogUser() *logrus.Entry {
	return AppLogger.WithField("component", "user")
}

// LogHTTP creates a logger for HTTP events
func LogHTTP() *logrus.Entry {
	return AppLogger.WithField("component", "http")
}

// LogDB creates a logger for database events
func LogDB() *logrus.Entry {
	return AppLogger.WithField("component", "database")
}

// SanitizeEmail redacts email for logging (shows domain but hides user)
func SanitizeEmail(email string) string {
	if email == "" {
		return "[empty]"
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		return "[invalid-email]"
	}

	user := parts[0]
	domain := parts[1]

	if len(user) <= 2 {
		return "**@" + domain
	}

	return user[:1] + "***" + user[len(user)-1:] + "@" + domain
}
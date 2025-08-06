package main

import (
	"gorm.io/gorm"
	"time"
)

type User struct {
	EmailAddress string `gorm:"unique;not null"`
	FullName     string
	Active       bool
	LastLoginAt  *time.Time
	gorm.Model
}

func (a *App) GetUserByEmail(email string) (*User, error) {
	var user User
	err := a.DB.Where("email_address = ? ", email).First(&user).Error
	return &user, err
}

func (a *App) GetOrCreateUser(email, fullName string) (*User, error) {
	// Check if user exists.
	user, err := a.GetUserByEmail(email)
	if err == nil {
		// User exists.
		return user, nil
	}

	// Create a new user.
	newUser := User{
		EmailAddress: email,
		FullName:     fullName,
		Active:       true,
	}

	err = a.DB.Create(&newUser).Error
	return &newUser, err
}

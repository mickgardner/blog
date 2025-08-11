package main

import (
	"crypto/rand"
	"errors"
	"gorm.io/gorm"
	"math/big"
	"time"
)

type Invitation struct {
	Email     string `gorm:"unique;not null"`
	InvitedBy uint   // Admin user
	Token     string `gorm:"unique;size:64"`
	ExpiresAt time.Time
	Used      bool `gorm:"default:false"`
	UsedAt    *time.Time
	gorm.Model
}

type User struct {
	EmailAddress string `gorm:"unique;not null"`
	FullName     string
	Active       bool
	IsAdmin      bool
	InvitedBy    *uint
	RegisteredAt *time.Time
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

func (a *App) CreateInvitation(adminUserID uint, email string) (*Invitation, error) {
	// Check if user already exists
	_, err := a.GetUserByEmail(email)
	if err == nil {
		return nil, errors.New("user already exists")
	}

	// Check for existing unused invitation
	var existingInvite Invitation
	err = a.DB.Where("email = ? AND used = ? AND expires_at > ?", email, false, time.Now()).First(&existingInvite).Error
	if err == nil {
		return nil, errors.New("Invitation already sent")
	}

	// Generate secure token
	token := generateSecureToken(64)

	invitation := Invitation{
		Email:     email,
		InvitedBy: adminUserID,
		Token:     token,
		ExpiresAt: time.Now().Add(7 * 24 * time.Hour), // 7 days
		Used:      false,
	}

	err = a.DB.Create(&invitation).Error
	return &invitation, err
}

func (a *App) ValidateInvitationToken(token string) (*Invitation, error) {
	var invitation Invitation
	err := a.DB.Where("token = ? AND used = ? AND expires_at > ?", token, false, time.Now()).First(&invitation).Error
	return &invitation, err
}

func (a *App) CompleteRegistration(token, email, fullName string) (*User, error) {
	// Validate invitation
	invitation, err := a.ValidateInvitationToken(token)
	if err != nil || invitation.Email != email {
		return nil, errors.New("invalid invitation")
	}

	// Create user
	user := User{
		EmailAddress: email,
		FullName:     fullName,
		Active:       true,
		IsAdmin:      false,
		InvitedBy:    &invitation.InvitedBy,
		RegisteredAt: &time.Time{},
	}
	*user.RegisteredAt = time.Now()

	err = a.DB.Create(&user).Error
	if err != nil {
		return nil, err
	}

	// Mark invitation as used
	invitation.Used = true
	invitation.UsedAt = &time.Time{}
	*invitation.UsedAt = time.Now()
	a.DB.Save(&invitation)

	return &user, nil
}

func generateSecureToken(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	token := make([]byte, length)

	for i := range token {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		token[i] = charset[num.Int64()]
	}

	return string(token)
}

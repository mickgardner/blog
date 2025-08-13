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
	PasswordHash string
	FullName     string
	Active       bool
	IsAdmin      bool
	EmailVerified bool `gorm:"default:false"`
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


// ValidatePassword checks if password meets requirements
func (u *User) ValidatePassword(password string) error {
	return CheckPassword(password, u.PasswordHash)
}

func (a *App) CreateUser(email, password, fullName string) (*User, error) {
	// Check if user exists by email
	_, err := a.GetUserByEmail(email)
	if err == nil {
		return nil, errors.New("user with this email already exists")
	}

	// Hash password
	passwordHash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}

	// Create new user
	newUser := User{
		EmailAddress:  email,
		PasswordHash:  passwordHash,
		FullName:      fullName,
		Active:        true,
		EmailVerified: false,
	}

	err = a.DB.Create(&newUser).Error
	return &newUser, err
}

func (a *App) AuthenticateUser(email, password string) (*User, error) {
	user, err := a.GetUserByEmail(email)
	if err != nil {
		return nil, errors.New("invalid email or password")
	}

	if !user.Active {
		return nil, errors.New("account is disabled")
	}

	// Handle case where user doesn't have a password yet (migration scenario)
	if user.PasswordHash == "" {
		return nil, errors.New("account setup incomplete - please contact administrator")
	}

	err = user.ValidatePassword(password)
	if err != nil {
		return nil, errors.New("invalid email or password")
	}

	return user, nil
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

func (a *App) CompleteRegistration(token, email, password, fullName string) (*User, error) {
	// Validate invitation
	invitation, err := a.ValidateInvitationToken(token)
	if err != nil || invitation.Email != email {
		return nil, errors.New("invalid invitation")
	}

	// Hash password
	passwordHash, err := HashPassword(password)
	if err != nil {
		return nil, err
	}

	// Create user
	user := User{
		EmailAddress:  email,
		PasswordHash:  passwordHash,
		FullName:      fullName,
		Active:        true,
		IsAdmin:       false,
		EmailVerified: false,
		InvitedBy:     &invitation.InvitedBy,
		RegisteredAt:  &time.Time{},
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

// GetFormattedRegistrationDate returns a nicely formatted registration date
func (user *User) GetFormattedRegistrationDate() string {
	if user.RegisteredAt == nil {
		return "Unknown"
	}
	return user.RegisteredAt.Format("January 2006")
}

// GetFormattedLastLogin returns a nicely formatted last login date
func (user *User) GetFormattedLastLogin() string {
	if user.LastLoginAt == nil {
		return "Never"
	}
	return user.LastLoginAt.Format("Jan 2, 2006")
}

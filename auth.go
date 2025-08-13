package main

import (
	"crypto/rand"
	"errors"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/gofiber/storage/redis/v3"
	"golang.org/x/crypto/bcrypt"
	"log"
	"math/big"
	"strconv"
	"time"
)

type VerificationCode struct {
	Email     string `gorm:"index"`
	Code      string `gorm:"size:10"`
	ExpiresAt time.Time
	Used      bool `gorm:"default:false"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type PasswordResetToken struct {
	Email     string `gorm:"index"`
	Token     string `gorm:"unique;size:64"`
	ExpiresAt time.Time
	Used      bool `gorm:"default:false"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Generate a cryptographically secure 6-digit code
func GenerateSecureCode() string {
	const digits = "0123456789"
	code := make([]byte, 6)

	for i := range code {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		code[i] = digits[num.Int64()]
	}

	return string(code)
}

// HashPassword creates a bcrypt hash of the password
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(hash), err
}

// CheckPassword verifies a password against its hash
func CheckPassword(password, hash string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}

func (a *App) CreateVerificationCode(email string) (*VerificationCode, error) {
	// First: invalidate any existing unused codes for this email
	a.DB.Model(&VerificationCode{}).
		Where("email = ? AND used = ? AND expires_at > ?", email, false, time.Now()).
		Update("used", true)

	code := GenerateSecureCode()

	verification := VerificationCode{
		Email:     email,
		Code:      code,
		ExpiresAt: time.Now().Add(15 * time.Minute),
		Used:      false,
	}

	err := a.DB.Create(&verification).Error
	return &verification, err
}

func (a *App) VerifyCode(email, inputCode string) (*VerificationCode, error) {
	var verification VerificationCode

	err := a.DB.Where("email = ? AND code = ? AND used = ? AND expires_at > ?", email, inputCode, false, time.Now()).First(&verification).Error
	if err != nil {
		// we didn't find the code or it has expired.
		return nil, err
	}

	verification.Used = true
	a.DB.Save(&verification)

	return &verification, nil
}

func (a *App) CleanupExpiredCodes() {
	a.DB.Where("expires_at < ?", time.Now()).Delete(&VerificationCode{})
}

func (a *App) CleanupExpiredTokens() {
	a.DB.Where("expires_at < ?", time.Now()).Delete(&PasswordResetToken{})
}

// GenerateSecureToken creates a secure random token for password reset
func GenerateSecureToken(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	token := make([]byte, length)

	for i := range token {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		token[i] = charset[num.Int64()]
	}

	return string(token)
}

func (a *App) CreatePasswordResetToken(email string) (*PasswordResetToken, error) {
	// Check if user exists and is active
	user, err := a.GetUserByEmail(email)
	if err != nil {
		return nil, errors.New("user not found")
	}
	if !user.Active {
		return nil, errors.New("account is disabled")
	}

	// Invalidate any existing unused tokens for this email
	a.DB.Model(&PasswordResetToken{}).
		Where("email = ? AND used = ? AND expires_at > ?", email, false, time.Now()).
		Update("used", true)

	token := GenerateSecureToken(64)

	resetToken := PasswordResetToken{
		Email:     email,
		Token:     token,
		ExpiresAt: time.Now().Add(1 * time.Hour), // 1 hour expiration
		Used:      false,
	}

	err = a.DB.Create(&resetToken).Error
	return &resetToken, err
}

func (a *App) ValidatePasswordResetToken(token string) (*PasswordResetToken, error) {
	var resetToken PasswordResetToken

	err := a.DB.Where("token = ? AND used = ? AND expires_at > ?", token, false, time.Now()).First(&resetToken).Error
	if err != nil {
		return nil, err
	}

	return &resetToken, nil
}

func (a *App) ResetPassword(token, newPassword string) error {
	// Validate token
	resetToken, err := a.ValidatePasswordResetToken(token)
	if err != nil {
		return errors.New("invalid or expired token")
	}

	// Get user
	user, err := a.GetUserByEmail(resetToken.Email)
	if err != nil {
		return errors.New("user not found")
	}

	// Hash new password
	passwordHash, err := HashPassword(newPassword)
	if err != nil {
		return err
	}

	// Update user password
	user.PasswordHash = passwordHash
	err = a.DB.Save(user).Error
	if err != nil {
		return err
	}

	// Mark token as used
	resetToken.Used = true
	a.DB.Save(&resetToken)

	return nil
}

// SESSION MANAGEMENT

//  - CreateUserSession - Create session after successful login
//  - GetCurrentUser - Get current logged-in user
//  - IsAuthenticated - Quick check if user is logged in
//  - DestroySession - Logout functionality

func (a *App) SetupSessions() {
	redisDB, err := strconv.Atoi(a.Config.RedisDB)
	if err != nil {
		redisDB = 0
	}

	redisPort, err := strconv.Atoi(a.Config.RedisPort)
	if err != nil {
		redisPort = 6379
	}

	storage := redis.New(redis.Config{
		Host:     a.Config.RedisURL,
		Port:     redisPort,
		Username: "",
		Password: a.Config.RedisPassword,
		Database: redisDB,
		Reset:    false,
	})

	a.SessionStore = session.New(session.Config{
		Storage:        storage,
		KeyLookup:      "cookie:session_id",
		CookieSecure:   false,
		CookieHTTPOnly: true,
		Expiration:     24 * time.Hour,
	})

	log.Println("Session store configuration with Redis")
}

func (a *App) CreateUserSession(c *fiber.Ctx, user *User) error {
	sess, err := a.SessionStore.Get(c)
	if err != nil {
		return err
	}

	sess.Set("user_id", user.ID)
	sess.Set("user_email", user.EmailAddress)
	sess.Set("authenticated", true)

	// Update users last login time.
	user.LastLoginAt = &time.Time{}
	*user.LastLoginAt = time.Now()
	a.DB.Save(user)

	return sess.Save()
}

func (a *App) GetCurrentUser(c *fiber.Ctx) (*User, error) {
	sess, err := a.SessionStore.Get(c)
	if err != nil {
		return nil, err
	}

	userID := sess.Get("user_id")
	if userID == nil {
		return nil, errors.New("not authenticated")
	}

	var user User
	err = a.DB.First(&user, userID).Error
	return &user, err
}

func (a *App) IsAuthenticated(c *fiber.Ctx) bool {
	sess, err := a.SessionStore.Get(c)
	if err != nil {
		return false
	}

	authenticated := sess.Get("authenticated")
	return authenticated != nil && authenticated.(bool)
}

func (a *App) DestroySession(c *fiber.Ctx) error {
	sess, err := a.SessionStore.Get(c)
	if err != nil {
		return err
	}

	return sess.Destroy()
}

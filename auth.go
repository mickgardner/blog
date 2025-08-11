package main

import (
	"crypto/rand"
	"errors"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/session"
	"github.com/gofiber/storage/redis/v3"
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

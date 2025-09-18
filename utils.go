package main

import (
	"crypto/rand"
	"math/big"
)

// GenerateSecureToken creates a cryptographically secure random token
func GenerateSecureToken(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	token := make([]byte, length)

	for i := range token {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		token[i] = charset[num.Int64()]
	}

	return string(token)
}

// GenerateSecureCode creates a cryptographically secure numeric code
func GenerateSecureCode() string {
	const digits = "0123456789"
	code := make([]byte, 6)

	for i := range code {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(digits))))
		code[i] = digits[num.Int64()]
	}

	return string(code)
}

// GenerateSecurePassword creates a secure random password
func GenerateSecurePassword(length int) string {
	if length < 12 {
		length = 12 // Minimum secure length
	}

	// Character sets for password generation
	lowercase := "abcdefghijklmnopqrstuvwxyz"
	uppercase := "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	numbers := "0123456789"
	special := "!@#$%^&*"
	allChars := lowercase + uppercase + numbers + special

	password := make([]byte, length)

	// Helper function to get random character from charset
	getRandomChar := func(charset string) byte {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		return charset[num.Int64()]
	}

	// Ensure at least one character from each set
	password[0] = getRandomChar(lowercase)
	password[1] = getRandomChar(uppercase)
	password[2] = getRandomChar(numbers)
	password[3] = getRandomChar(special)

	// Fill the rest randomly
	for i := 4; i < length; i++ {
		password[i] = getRandomChar(allChars)
	}

	// Shuffle the password
	for i := len(password) - 1; i > 0; i-- {
		num, _ := rand.Int(rand.Reader, big.NewInt(int64(i+1)))
		j := num.Int64()
		password[i], password[j] = password[j], password[i]
	}

	return string(password)
}
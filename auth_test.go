package main

import (
	"fmt"
	"regexp"
	"testing"
)

func TestGenerateSecureCode(t *testing.T) {
	t.Run("Code length is exactly 6 digits", func(t *testing.T) {
		code := GenerateSecureCode()
		if len(code) != 6 {
			t.Errorf("Expected code length 6, got %d", len(code))
		}
	})

	t.Run("Code contains only digits 0-9", func(t *testing.T) {
		code := GenerateSecureCode()
		matched, _ := regexp.MatchString("^[0-9]{6}$", code)
		if !matched {
			t.Errorf("Code should only contain digits 0-9, got: %s", code)
		}
	})

	t.Run("Generated codes are unique", func(t *testing.T) {
		codes := make(map[string]bool)

		for i := 0; i < 100; i++ {
			code := GenerateSecureCode()
			if codes[code] {
				t.Errorf("Duplicate code generated: %s", code)
			}
			codes[code] = true
		}
	})

	t.Run("Code distribution looks random", func(t *testing.T) {
		digitCounts := make(map[string]int)

		for i := 0; i < 1000; i++ {
			code := GenerateSecureCode()
			firstDigit := string(code[0])
			digitCounts[firstDigit]++
		}

		digits := []string{"0", "1", "2", "3", "4", "5", "6", "7", "8", "9"}
		for _, digit := range digits {
			count := digitCounts[digit]
			if count < 50 {
				t.Errorf("Digit %s appears only %d times, seems non-random", digit, count)
			}
		}

		fmt.Println("First digit distribution: ")
		for _, digit := range digits {
			fmt.Printf("   %s: %d times\n", digit, digitCounts[digit])
		}
	})
}

func TestHashPassword(t *testing.T) {
	t.Run("Password hashing works", func(t *testing.T) {
		password := "testpassword123"
		hash, err := HashPassword(password)
		if err != nil {
			t.Errorf("Failed to hash password: %v", err)
		}
		if hash == "" {
			t.Error("Hash should not be empty")
		}
		if hash == password {
			t.Error("Hash should not equal original password")
		}
	})

	t.Run("Password verification works", func(t *testing.T) {
		password := "testpassword123"
		hash, err := HashPassword(password)
		if err != nil {
			t.Errorf("Failed to hash password: %v", err)
		}

		err = CheckPassword(password, hash)
		if err != nil {
			t.Errorf("Password verification failed: %v", err)
		}
	})

	t.Run("Wrong password fails verification", func(t *testing.T) {
		password := "testpassword123"
		wrongPassword := "wrongpassword"
		hash, err := HashPassword(password)
		if err != nil {
			t.Errorf("Failed to hash password: %v", err)
		}

		err = CheckPassword(wrongPassword, hash)
		if err == nil {
			t.Error("Wrong password should fail verification")
		}
	})
}

func TestGenerateSecureToken(t *testing.T) {
	t.Run("Token has correct length", func(t *testing.T) {
		token := GenerateSecureToken(64)
		if len(token) != 64 {
			t.Errorf("Expected token length 64, got %d", len(token))
		}
	})

	t.Run("Tokens are unique", func(t *testing.T) {
		tokens := make(map[string]bool)

		for i := 0; i < 100; i++ {
			token := GenerateSecureToken(32)
			if tokens[token] {
				t.Errorf("Duplicate token generated: %s", token)
			}
			tokens[token] = true
		}
	})

	t.Run("Token contains valid characters", func(t *testing.T) {
		token := GenerateSecureToken(64)
		matched, _ := regexp.MatchString("^[a-zA-Z0-9]+$", token)
		if !matched {
			t.Errorf("Token should only contain alphanumeric characters, got: %s", token)
		}
	})
}

func TestValidation(t *testing.T) {
	t.Run("Valid passwords pass validation", func(t *testing.T) {
		validPasswords := []string{"password123", "Test1234", "mySecureP@ss1"}
		for _, password := range validPasswords {
			valid, msg := isValidPassword(password)
			if !valid {
				t.Errorf("Password '%s' should be valid, got error: %s", password, msg)
			}
		}
	})

	t.Run("Invalid passwords fail validation", func(t *testing.T) {
		invalidPasswords := []string{"short", "nouppercase", "NOLOWERCASE", "NoNumbers"}
		for _, password := range invalidPasswords {
			valid, _ := isValidPassword(password)
			if valid {
				t.Errorf("Password '%s' should be invalid", password)
			}
		}
	})

	t.Run("Valid emails pass validation", func(t *testing.T) {
		validEmails := []string{"test@example.com", "user.name@domain.co.uk", "user+tag@example.org"}
		for _, email := range validEmails {
			if !isValidEmail(email) {
				t.Errorf("Email '%s' should be valid", email)
			}
		}
	})

	t.Run("Invalid emails fail validation", func(t *testing.T) {
		invalidEmails := []string{"notanemail", "@example.com", "user@", "user..name@example.com"}
		for _, email := range invalidEmails {
			if isValidEmail(email) {
				t.Errorf("Email '%s' should be invalid", email)
			}
		}
	})
}

func TestGenerateSecurePassword(t *testing.T) {
	t.Run("Password has correct length", func(t *testing.T) {
		password := GenerateSecurePassword(16)
		if len(password) != 16 {
			t.Errorf("Expected password length 16, got %d", len(password))
		}
	})

	t.Run("Password meets complexity requirements", func(t *testing.T) {
		password := GenerateSecurePassword(16)
		
		// Check for at least one lowercase
		hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
		if !hasLower {
			t.Error("Password should contain at least one lowercase letter")
		}
		
		// Check for at least one uppercase
		hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
		if !hasUpper {
			t.Error("Password should contain at least one uppercase letter")
		}
		
		// Check for at least one number
		hasNumber := regexp.MustCompile(`[0-9]`).MatchString(password)
		if !hasNumber {
			t.Error("Password should contain at least one number")
		}
		
		// Check for at least one special character
		hasSpecial := regexp.MustCompile(`[!@#$%^&*]`).MatchString(password)
		if !hasSpecial {
			t.Error("Password should contain at least one special character")
		}
	})

	t.Run("Generated passwords are unique", func(t *testing.T) {
		passwords := make(map[string]bool)
		
		for i := 0; i < 100; i++ {
			password := GenerateSecurePassword(16)
			if passwords[password] {
				t.Errorf("Duplicate password generated: %s", password)
			}
			passwords[password] = true
		}
	})

	t.Run("Minimum length is enforced", func(t *testing.T) {
		password := GenerateSecurePassword(8) // Request 8, should get 12
		if len(password) < 12 {
			t.Errorf("Password should be at least 12 characters, got %d", len(password))
		}
	})
}

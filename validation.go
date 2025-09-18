package main

import (
	"errors"
	"regexp"
	"strings"
	"unicode/utf8"
)

func isValidEmail(email string) bool {
	if len(email) > 254 {
		return false
	}

	// Check for consecutive dots or invalid patterns
	if strings.Contains(email, "..") || strings.HasPrefix(email, ".") || strings.HasSuffix(email, ".") {
		return false
	}

	// Basic email validation
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`)
	return emailRegex.MatchString(email)
}

func isValidFullName(name string) (bool, string) {
	name = strings.TrimSpace(name)

	if len(name) < 2 {
		return false, "Name must be at least 2 characters"
	}
	if len(name) > 100 {
		return false, "Name cannot exceed 100 characters"
	}
	if utf8.RuneCountInString(name) != len(name) {
		// Contains non-ASCII characters - could be valid but add extra checks
	}

	// Check for suspicious patterns
	nameRegex := regexp.MustCompile(`^[a-zA-Z\s\-'.]+$`)
	if !nameRegex.MatchString(name) {
		return false, "Name contains invalid characters"
	}

	return true, ""
}

func sanitizeInput(input string) string {
	// Trim whitespace
	input = strings.TrimSpace(input)

	// Remove null bytes and control characters
	input = strings.ReplaceAll(input, "\x00", "")

	return input
}

// ValidateUserInput validates user registration/profile input
type UserInput struct {
	Email    string
	FullName string
	Password string
}

func (u UserInput) Validate() error {
	// Sanitize inputs
	u.Email = sanitizeInput(u.Email)
	u.FullName = sanitizeInput(u.FullName)

	// Validate email
	if u.Email == "" {
		return errors.New("email is required")
	}
	if !isValidEmail(u.Email) {
		return errors.New("please enter a valid email address")
	}

	// Validate full name
	if u.FullName == "" {
		return errors.New("full name is required")
	}
	if valid, msg := isValidFullName(u.FullName); !valid {
		return errors.New(msg)
	}

	// Validate password if provided
	if u.Password != "" {
		if valid, msg := isValidPassword(u.Password); !valid {
			return errors.New(msg)
		}
	}

	return nil
}

// ValidateLoginInput validates login input
type LoginInput struct {
	Email    string
	Password string
}

func (l LoginInput) Validate() error {
	// Sanitize inputs
	l.Email = sanitizeInput(l.Email)

	// Validate required fields
	if l.Email == "" || l.Password == "" {
		return errors.New("email and password are required")
	}

	// Validate email format
	if !isValidEmail(l.Email) {
		return errors.New("please enter a valid email address")
	}

	return nil
}

// ValidateArticleInput validates article creation/update input
type ArticleInput struct {
	Title string
	Slug  string
	Body  string
}

func (a ArticleInput) Validate() error {
	// Sanitize inputs
	a.Title = sanitizeInput(a.Title)
	a.Slug = sanitizeInput(a.Slug)
	a.Body = strings.TrimSpace(a.Body)

	// Validate required fields
	if a.Title == "" {
		return errors.New("title is required")
	}
	if a.Slug == "" {
		return errors.New("slug is required")
	}
	if a.Body == "" {
		return errors.New("content is required")
	}

	// Validate slug format
	if !isValidSlug(a.Slug) {
		return errors.New("slug must contain only lowercase letters, numbers, and hyphens")
	}

	return nil
}

// isValidSlug validates article slug format
func isValidSlug(slug string) bool {
	if slug == "" {
		return false
	}

	// Check for valid characters (lowercase letters, numbers, hyphens)
	for _, char := range slug {
		if !((char >= 'a' && char <= 'z') || (char >= '0' && char <= '9') || char == '-') {
			return false
		}
	}

	// Cannot start or end with hyphen
	if strings.HasPrefix(slug, "-") || strings.HasSuffix(slug, "-") {
		return false
	}

	// Cannot have consecutive hyphens
	if strings.Contains(slug, "--") {
		return false
	}

	return true
}


func isValidPassword(password string) (bool, string) {
	if len(password) < 8 {
		return false, "Password must be at least 8 characters long"
	}
	if len(password) > 128 {
		return false, "Password cannot exceed 128 characters"
	}

	var hasLower, hasUpper, hasNumber, hasSpecial bool

	for _, char := range password {
		switch {
		case char >= 'a' && char <= 'z':
			hasLower = true
		case char >= 'A' && char <= 'Z':
			hasUpper = true
		case char >= '0' && char <= '9':
			hasNumber = true
		case char == '!' || char == '@' || char == '#' || char == '$' ||
			 char == '%' || char == '^' || char == '&' || char == '*' ||
			 char == '(' || char == ')' || char == '-' || char == '_' ||
			 char == '=' || char == '+' || char == '[' || char == ']' ||
			 char == '{' || char == '}' || char == '|' || char == '\\' ||
			 char == ':' || char == ';' || char == '"' || char == '\'' ||
			 char == '<' || char == '>' || char == ',' || char == '.' ||
			 char == '?' || char == '/' || char == '~' || char == '`':
			hasSpecial = true
		}
	}

	var missing []string
	if !hasLower {
		missing = append(missing, "lowercase letter")
	}
	if !hasUpper {
		missing = append(missing, "uppercase letter")
	}
	if !hasNumber {
		missing = append(missing, "number")
	}
	if !hasSpecial {
		missing = append(missing, "special character")
	}

	if len(missing) > 0 {
		return false, "Password must contain at least one " + strings.Join(missing, ", ")
	}

	// Check for common weak patterns
	lowerPassword := strings.ToLower(password)
	weakPatterns := []string{
		"password", "123456", "qwerty", "abc123", "admin", "login",
		"welcome", "monkey", "letmein", "dragon", "master", "superman",
	}

	for _, pattern := range weakPatterns {
		if strings.Contains(lowerPassword, pattern) {
			return false, "Password contains common weak patterns"
		}
	}

	return true, ""
}

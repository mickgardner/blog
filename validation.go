package main

import (
	"regexp"
	"strings"
	"unicode/utf8"
)

func isValidEmail(email string) bool {
	if len(email) > 254 {
		return false
	}

	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+[a-zA-Z]{2,}$`)
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

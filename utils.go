package main

import (
	"bytes"
	"crypto/rand"
	"html/template"
	"math/big"

	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/renderer/html"
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

// MarkdownToHTML converts markdown content to HTML using goldmark
func MarkdownToHTML(markdown string) (template.HTML, error) {
	// Configure goldmark with extensions
	md := goldmark.New(
		goldmark.WithExtensions(
			extension.GFM,        // GitHub Flavored Markdown
			extension.Table,      // Tables
			extension.Strikethrough, // ~~strikethrough~~
			extension.Linkify,    // Auto-link URLs
			extension.TaskList,   // - [ ] task lists
		),
		goldmark.WithParserOptions(
			parser.WithAutoHeadingID(), // Auto-generate heading IDs
		),
		goldmark.WithRendererOptions(
			html.WithHardWraps(),   // Convert line breaks to <br>
			html.WithXHTML(),       // XHTML compatible output
			html.WithUnsafe(),      // Allow raw HTML (for images, etc.)
		),
	)

	var buf bytes.Buffer
	if err := md.Convert([]byte(markdown), &buf); err != nil {
		return "", err
	}

	return template.HTML(buf.String()), nil
}

// IsMarkdownContent checks if content contains common markdown syntax
func IsMarkdownContent(content string) bool {
	// Simple heuristics to detect markdown content
	markdownIndicators := []string{
		"#", "##", "###",      // Headers
		"**", "__",            // Bold
		"*", "_",              // Italic
		"- ", "* ", "+ ",      // Lists
		"```", "`",            // Code
		"[", "](",             // Links
		"![", "![alt](",       // Images
		"|",                   // Tables
		">",                   // Blockquotes
	}

	for _, indicator := range markdownIndicators {
		if bytes.Contains([]byte(content), []byte(indicator)) {
			return true
		}
	}
	return false
}

// SanitizeMarkdown performs basic sanitization on markdown content
func SanitizeMarkdown(markdown string) string {
	// Basic sanitization - can be extended with more rules
	// For now, just trim whitespace
	return string(bytes.TrimSpace([]byte(markdown)))
}
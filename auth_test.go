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

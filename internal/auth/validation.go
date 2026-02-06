package auth

import (
	"fmt"
	"strings"
	"unicode"
)

// ValidatePassword validates password against the spec requirements.
// Per NIST 800-63B: minimum 12 characters, no character class requirements.
// The spec says: "No character class requirements (NIST 800-63B compliant)"
func ValidatePassword(password string, minLength int) error {
	if minLength == 0 {
		minLength = 12
	}

	// Check minimum length
	if len(password) < minLength {
		return fmt.Errorf("password must be at least %d characters long", minLength)
	}

	// Check maximum length (prevent DoS via extremely long passwords)
	if len(password) > 128 {
		return fmt.Errorf("password must be at most 128 characters long")
	}

	// Check for common weak patterns
	lower := strings.ToLower(password)
	commonPasswords := []string{
		"password1234", "123456789012", "qwertyuiopas",
	}
	for _, common := range commonPasswords {
		if lower == common {
			return fmt.Errorf("password is too common")
		}
	}

	// Ensure password is not entirely one character type repeated
	if isRepeatingChar(password) {
		return fmt.Errorf("password cannot be a single repeating character")
	}

	return nil
}

// isRepeatingChar checks if the password is just the same character repeated
func isRepeatingChar(s string) bool {
	if len(s) == 0 {
		return false
	}
	runes := []rune(s)
	first := runes[0]
	for _, r := range runes[1:] {
		if r != first {
			return false
		}
	}
	return true
}

// EstimatePasswordStrength returns a simple strength estimate (0-4)
func EstimatePasswordStrength(password string) int {
	score := 0

	if len(password) >= 12 {
		score++
	}
	if len(password) >= 16 {
		score++
	}

	hasLower, hasUpper, hasDigit, hasSpecial := false, false, false, false
	for _, r := range password {
		switch {
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSpecial = true
		}
	}

	charTypes := 0
	if hasLower {
		charTypes++
	}
	if hasUpper {
		charTypes++
	}
	if hasDigit {
		charTypes++
	}
	if hasSpecial {
		charTypes++
	}

	if charTypes >= 3 {
		score++
	}
	if charTypes >= 4 {
		score++
	}

	return score
}

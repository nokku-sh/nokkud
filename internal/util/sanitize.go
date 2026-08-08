package util

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

var posixUserRE = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,31}$`)

// ValidatePrincipal ensures the principal is a safe POSIX username.
func ValidatePrincipal(principal string) error {
	if principal == "" {
		return fmt.Errorf("empty username")
	}
	if !posixUserRE.MatchString(principal) {
		return fmt.Errorf("invalid username")
	}
	return nil
}

// ToSnakeCase converts an arbitrary string into a safe, snake_case format.
func ToSnakeCase(s string) string {
	var b strings.Builder
	b.Grow(len(s))

	lastWasUnderscore := true // Start true to drop leading underscores

	for _, r := range s {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			b.WriteRune(unicode.ToLower(r))
			lastWasUnderscore = false
		} else if !lastWasUnderscore {
			b.WriteByte('_')
			lastWasUnderscore = true
		}
	}

	res := b.String()
	if len(res) > 0 && res[len(res)-1] == '_' {
		res = res[:len(res)-1]
	}

	// Fallback if the string was entirely invalid characters
	if res == "" {
		return "untitled"
	}

	return res
}

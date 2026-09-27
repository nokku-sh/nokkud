package util

import (
	"fmt"
	"regexp"
	"strings"
	"unicode"
)

// maxSnakeCaseLen bounds the result so it always fits a single filename.
const maxSnakeCaseLen = 64

// posixUserRE matches the shadow-utils relaxed name rules, so LDAP and SSSD
// names like john.doe pass. Keep in sync with the username pattern in protos.
var posixUserRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9._-]*\$?$`)

// ValidatePrincipal checks that principal is a safe POSIX username.
func ValidatePrincipal(principal string) error {
	if len(principal) > 32 || !posixUserRE.MatchString(principal) {
		return fmt.Errorf("invalid username %q", principal)
	}
	return nil
}

// ToSnakeCase converts s into a safe, snake_case filename component.
func ToSnakeCase(s string) string {
	var b strings.Builder
	b.Grow(len(s))

	lastWasUnderscore := true // Start true so leading separators are dropped

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
	if len(res) > maxSnakeCaseLen {
		res = strings.ToValidUTF8(res[:maxSnakeCaseLen], "")
	}
	if len(res) > 0 && res[len(res)-1] == '_' {
		res = res[:len(res)-1]
	}

	if res == "" {
		return "untitled"
	}

	return res
}

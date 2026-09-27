package state

import (
	"fmt"
	"regexp"
)

// posixUserRE matches the shadow-utils relaxed name rules, so LDAP and SSSD
// names like john.doe pass. Keep in sync with the username pattern in protos.
var posixUserRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9._-]*\$?$`)

// validatePrincipal checks that principal is a safe POSIX username.
func validatePrincipal(principal string) error {
	if len(principal) > 32 || !posixUserRE.MatchString(principal) {
		return fmt.Errorf("invalid username %q", principal)
	}
	return nil
}

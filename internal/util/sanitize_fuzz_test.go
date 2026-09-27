package util

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// FuzzToSnakeCase checks the invariants the recorder relies on: the result
// must never be empty, must be a single filename component (no separators,
// no traversal), and must fit NAME_MAX so recording files can always be
// created.
func FuzzToSnakeCase(f *testing.F) {
	f.Add("")
	f.Add("untitled")
	f.Add("../../etc/passwd")
	f.Add("a_b")
	f.Add("-")
	f.Add("日本語タイトル")
	f.Add(strings.Repeat("x", 300))
	f.Add("İstanbul")

	f.Fuzz(func(t *testing.T, s string) {
		res := ToSnakeCase(s)

		if res == "" {
			t.Fatalf("ToSnakeCase(%q) returned empty string", s)
		}
		if strings.ContainsAny(res, "/\\\x00") {
			t.Fatalf("ToSnakeCase(%q) = %q contains a path separator or NUL", s, res)
		}
		if res == "." || res == ".." {
			t.Fatalf("ToSnakeCase(%q) = %q is a traversal component", s, res)
		}
		if !utf8.ValidString(res) {
			t.Fatalf("ToSnakeCase(%q) = %q is not valid UTF-8", s, res)
		}
		// The result becomes part of a filename. 255 is NAME_MAX on Linux.
		if len(res) > 255 {
			t.Fatalf("ToSnakeCase(%q) produced a %d-byte name, exceeds NAME_MAX", s, len(res))
		}
	})
}

func TestValidatePrincipal(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"root", "deploy", "_svc", "john.doe", "John", "ec2-user", "host$", strings.Repeat("a", 32)} {
		require.NoError(t, ValidatePrincipal(name), name)
	}
	for _, name := range []string{"", ".", "..", "-rf", "0abc", "a/b", "a b", "üser", "a$b", strings.Repeat("a", 33)} {
		assert.Error(t, ValidatePrincipal(name), name)
	}
}

// FuzzValidatePrincipal checks an accepted name is always safe as a path
// component.
func FuzzValidatePrincipal(f *testing.F) {
	f.Add("roxas")
	f.Add("..")
	f.Add("john.doe")
	f.Fuzz(func(t *testing.T, principal string) {
		if ValidatePrincipal(principal) != nil {
			return
		}
		if principal == "." || principal == ".." || strings.ContainsAny(principal, "/\x00") {
			t.Fatalf("ValidatePrincipal(%q) accepted an unsafe name", principal)
		}
	})
}

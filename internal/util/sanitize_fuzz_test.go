package util

import (
	"strings"
	"testing"
	"unicode/utf8"
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

// FuzzValidatePrincipal checks the validator only accepts names the POSIX
// regex matches: everything else must be rejected.
func FuzzValidatePrincipal(f *testing.F) {
	f.Add("")
	f.Add("roxas")
	f.Add("0abc")
	f.Add("_")
	f.Add("a-b_1")
	f.Add(strings.Repeat("a", 32))
	f.Add(strings.Repeat("a", 33))
	f.Add("A")
	f.Add("üser")

	f.Fuzz(func(t *testing.T, principal string) {
		if err := ValidatePrincipal(principal); err != nil {
			return
		}
		if !posixUserRE.MatchString(principal) {
			t.Fatalf("ValidatePrincipal(%q) accepted a non-POSIX name", principal)
		}
	})
}

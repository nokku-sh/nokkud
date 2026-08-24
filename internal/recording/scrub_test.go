package recording

import (
	"bytes"
	"strings"
	"testing"
)

func TestScrubber_Assignment(t *testing.T) {
	s := NewScrubber()
	got := string(rubAndFlush(t, s, []byte("export AWS_SECRET_ACCESS_KEY=supersecret\n")))
	if strings.Contains(got, "supersecret") {
		t.Fatalf("secret value leaked: %q", got)
	}
	if !strings.Contains(got, redaction) {
		t.Fatalf("expected mask in output: %q", got)
	}
	// The key name is kept so the line stays readable.
	if !strings.Contains(got, "AWS_SECRET_ACCESS_KEY") {
		t.Fatalf("key name lost: %q", got)
	}
}

func TestScrubber_AWSAccessKey(t *testing.T) {
	s := NewScrubber()
	got := string(rubAndFlush(t, s, []byte("using credentials AKIAIOSFODNN7EXAMPLE in config\n")))
	if strings.Contains(got, "AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("aws key leaked: %q", got)
	}
}

func TestScrubber_PrivateKeyAcrossReads(t *testing.T) {
	s := NewScrubber()
	// Emit the key in several reads; the open block must be held whole.
	var out []byte
	for _, chunk := range []string{
		"-----BEGIN RSA PRIVATE KEY-----\n",
		"MIIEowIBAAKCAQEA\n",
		"-----END RSA PRIVATE KEY-----\n",
	} {
		out = append(out, s.Rub([]byte(chunk))...)
	}
	out = append(out, s.Flush()...)
	if strings.Contains(string(out), "PRIVATE KEY") {
		t.Fatalf("key leaked: %q", out)
	}
	if !strings.Contains(string(out), redaction) {
		t.Fatalf("expected mask in output: %q", out)
	}
}

func TestScrubber_EmitsCompleteLinesPromptly(t *testing.T) {
	s := NewScrubber()
	// A complete line is released on the Rub call, not held until close.
	got := string(s.Rub([]byte("token=abc123\n")))
	if !strings.Contains(got, redaction) || strings.Contains(got, "abc123") {
		t.Fatalf("complete line not redacted: %q", got)
	}
	// The partial line is held until the newline arrives.
	if out := s.Rub([]byte("secret=")); len(out) != 0 {
		t.Fatalf("partial line should be held, got %q", out)
	}
	got = string(s.Rub([]byte("hunter2\n")))
	if !strings.Contains(got, redaction) || strings.Contains(got, "hunter2") {
		t.Fatalf("completed line not redacted: %q", got)
	}
}

func TestScrubber_Passthrough(t *testing.T) {
	s := NewScrubber()
	plain := "hello world\nls -la /tmp\n"
	got := string(rubAndFlush(t, s, []byte(plain)))
	if got != plain {
		t.Fatalf("plain text altered: %q", got)
	}
}

func TestScrubber_FlushTail(t *testing.T) {
	s := NewScrubber()
	// A partial line with no newline is held; Flush must release it redacted.
	if got := s.Rub([]byte("token=abc123")); len(got) != 0 {
		t.Fatalf("expected partial line held, got %q", got)
	}
	tail := string(s.Flush())
	if !strings.Contains(tail, redaction) || strings.Contains(tail, "abc123") {
		t.Fatalf("flush tail not redacted: %q", tail)
	}
}

func TestScrubber_NoPanic(t *testing.T) {
	_ = t
	s := NewScrubber()
	inputs := [][]byte{
		{},
		[]byte("a"),
		[]byte("\xff\xfe"),
		bytes.Repeat([]byte("x"), 70<<10),
	}
	for _, in := range inputs {
		_ = s.Rub(in)
	}
	_ = s.Flush()
}

func rubAndFlush(t *testing.T, s *Scrubber, p []byte) []byte {
	t.Helper()
	var out []byte
	out = append(out, s.Rub(p)...)
	out = append(out, s.Flush()...)
	return out
}

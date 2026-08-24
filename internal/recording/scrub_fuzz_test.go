package recording

import (
	"bytes"
	"strings"
	"testing"
)

// fuzzSecret is injected into every fuzz input; it must never appear in the
// scrubber's output no matter how the surrounding bytes or read boundaries
// are shaped.
const fuzzSecret = "AKIAIOSFODNN7EXAMPLE"

// FuzzScrubberNeverLeaks drives the Scrubber with arbitrary bytes and chunk
// splits, always keeping an AWS access-key secret somewhere in the stream.
// The output after Flush must never contain the secret, and the emitted
// bytes must be bounded (a buffering bug would duplicate or grow the input).
func FuzzScrubberNeverLeaks(f *testing.F) {
	f.Add([]byte("echo hello\n"), uint8(1))
	f.Add([]byte("export AWS_SECRET_ACCESS_KEY=z\n"), uint8(2))
	f.Add([]byte("git clone https://git@github.com:/repo\n"), uint8(0))

	f.Fuzz(func(t *testing.T, data []byte, split uint8) {
		if len(data) > 8<<10 {
			data = data[:8<<10]
		}

		// Interleave the secret into the stream, guarded by spaces so the
		// word boundaries of the pattern hold.
		mid := len(data) / 2
		left := data[:mid]
		right := data[mid:]
		content := make([]byte, 0, len(left)+len(fuzzSecret)+2+len(right))
		content = append(content, left...)
		content = append(content, ' ')
		content = append(content, []byte(fuzzSecret)...)
		content = append(content, ' ')
		content = append(content, right...)

		s := NewScrubber()
		var out []byte
		// Feed the stream as two chunks split at a fuzz-chosen point so the
		// secret and surrounding bytes land across read boundaries.
		i := int(split) % (len(content) + 1)
		out = append(out, s.Rub(content[:i])...)
		out = append(out, s.Rub(content[i:])...)
		out = append(out, s.Flush()...)

		if bytes.Contains(out, []byte(fuzzSecret)) {
			t.Fatalf("secret leaked: %q", out)
		}
		// Never more than the input plus a bounded headroom, and never empty
		// when the input carried content.
		if len(out) > len(content)+8192 {
			t.Fatalf("output grew unbounded: in=%d out=%d", len(content), len(out))
		}
		if len(out) == 0 && len(content) > 0 {
			t.Fatalf("output empty for non-empty input: %q", content)
		}
		// The mask must make it through, so the output is never just a
		// silently-dropped secret.
		if !strings.Contains(string(out), redaction) {
			t.Fatalf("expected a mask in the output: %q", out)
		}
	})
}

package recording

import (
	"bytes"
	"regexp"
)

// redaction is the mask substituted for a detected credential value.
const redaction = "<redacted>"

// maxBuf bounds a single held line so a line that never ends (progress
// spinners, or an open private key) is force-flushed instead of growing
// unbounded.
const maxBuf = 64 << 10

// patternRepl pairs a credential regex with its replacement. The assignment
// pattern keeps the left-hand key so a redacted line stays readable:
// "SECRET=abcdef" becomes "SECRET=<redacted>" instead of losing the name.
type patternRepl struct {
	re   *regexp.Regexp
	repl []byte
}

var (
	privateKeyRE = regexp.MustCompile(
		`(?s)-----BEGIN [^-]+PRIVATE KEY-----.*?-----END [^-]+PRIVATE KEY-----`,
	)
	awsAccessRE  = regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)
	githubRE     = regexp.MustCompile(`\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b`)
	githubPatRE  = regexp.MustCompile(`(?i)\bgithub_pat_[A-Za-z0-9_]{20,}\b`)
	assignmentRE = regexp.MustCompile(
		`(?i)\b([A-Za-z0-9_]*(?:secret|token|password|passwd|passphrase|apikey|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|credential|bearer|auth)[A-Za-z0-9_]*)\b\s*[=:]\s*["']?[^\s"',;]+`,
	)
	authzHeaderRE = regexp.MustCompile(
		`(?i)\bauthorization:[ \t]*(?:bearer|basic|token)?[ \t]*[^\s]+`,
	)
)

var secretPatterns = []patternRepl{
	{privateKeyRE, []byte(redaction)},
	{awsAccessRE, []byte(redaction)},
	{githubRE, []byte(redaction)},
	{githubPatRE, []byte(redaction)},
	{assignmentRE, []byte("$1=" + redaction)},
	{authzHeaderRE, []byte("authorization: " + redaction)},
}

// Scrubber masks common credentials in terminal output before it is recorded.
//
// It is line-oriented so recorded output keeps its real timing: a complete
// line is redacted and emitted as soon as its newline arrives, and only the
// trailing partial line is held. A multi-line private key block is held whole
// so it is never split across emissions, which would leak its prefix.
type Scrubber struct {
	patterns []patternRepl
	buf      []byte
}

// NewScrubber builds a Scrubber with the default credential patterns.
func NewScrubber() *Scrubber {
	return &Scrubber{patterns: secretPatterns}
}

// Rub consumes an output chunk and returns the redacted bytes safe to emit
// now. Complete lines are redacted and released; a trailing partial line, or
// an open private key block, is held for the next chunk.
func (s *Scrubber) Rub(p []byte) []byte {
	s.buf = append(s.buf, p...)
	if len(s.buf) >= maxBuf {
		out := s.redact(s.buf)
		s.buf = nil
		return out
	}
	nl := bytes.LastIndexByte(s.buf, '\n')
	if nl < 0 || openPrivateKey(s.buf, nl) {
		return nil
	}
	out := s.redact(s.buf[:nl+1])
	s.buf = s.buf[nl+1:]
	return out
}

// Flush returns the redacted tail still being held, for writing at close.
func (s *Scrubber) Flush() []byte {
	out := s.redact(s.buf)
	s.buf = nil
	return out
}

// redact replaces every detected credential in b with its mask.
func (s *Scrubber) redact(b []byte) []byte {
	out := b
	for _, p := range s.patterns {
		if p.re.Match(out) {
			out = p.re.ReplaceAll(out, p.repl)
		}
	}
	return out
}

// openPrivateKey reports whether cutting the buffer at the newline nl would
// split a BEGIN/END private key block, which would leak its prefix into the
// emitted part.
func openPrivateKey(buf []byte, nl int) bool {
	begin := bytes.Index(buf, []byte("-----BEGIN"))
	if begin < 0 {
		return false
	}
	end := bytes.Index(buf[begin+len("-----BEGIN"):], []byte("-----END"))
	if end < 0 {
		return nl >= begin
	}
	endPos := begin + len("-----BEGIN") + end + len("-----END")
	return nl >= begin && nl < endPos
}

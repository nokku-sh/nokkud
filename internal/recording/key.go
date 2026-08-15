// Package recording holds the daemon's recording pipeline. The recorder
// captures terminal sessions to gzipped asciicast files, the uploader seals
// each flush batch at the edge and streams it to the backend, and the key
// helpers mirror the backend's so fingerprints match byte for byte. The
// backend never inspects chunk contents.
package recording

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
)

const KeySize = 32

// ParsePublicKey decodes a base64 X25519 public key and checks its size.
func ParsePublicKey(encoded string) ([]byte, error) {
	pub, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("invalid recording public key: not base64")
	}
	if len(pub) != KeySize {
		return nil, fmt.Errorf(
			"invalid recording public key: got %d bytes, want %d",
			len(pub),
			KeySize,
		)
	}
	return pub, nil
}

// Fingerprint returns the first 16 hex chars of the key's SHA-256. It
// identifies which key sealed a recording and detects key changes.
func Fingerprint(pub []byte) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

// Key validates a base64 X25519 public key and returns it with its
// fingerprint, or ok=false when the key is empty or malformed.
func Key(pubkeyB64 string) (pubkey, fingerprint string, ok bool) {
	if pubkeyB64 == "" {
		return "", "", false
	}
	pub, err := ParsePublicKey(pubkeyB64)
	if err != nil {
		return "", "", false
	}
	return pubkeyB64, Fingerprint(pub), true
}

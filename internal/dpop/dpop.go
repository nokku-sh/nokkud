// Package dpop signs DPoP (RFC 9449) proofs client-side with the machine's
// signing key, TPM-backed or the software fallback. Every proof embeds the
// public JWK, so the backend can verify the signature and bind the session
// to the key's thumbprint (jkt) without any pre-registration step.
package dpop

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/cryptosigner"
)

// ProoferOptions configures a Proofer.
type ProoferOptions struct {
	// Now injects the clock for tests.
	Now func() time.Time
}

// Proofer signs DPoP proofs with an ECDSA P-256 [crypto.Signer]. The signer
// must sign digests directly (both the TPM and software signers do).
type Proofer struct {
	opaque jose.OpaqueSigner
	jwk    *jose.JSONWebKey
	now    func() time.Time
}

// NewProofer builds a proofer around key.
func NewProofer(key crypto.Signer, opts ProoferOptions) (*Proofer, error) {
	pub, ok := key.Public().(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("dpop: signer must be an ECDSA P-256 key")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return &Proofer{
		opaque: cryptosigner.Opaque(key),
		jwk:    &jose.JSONWebKey{Key: pub},
		now:    opts.Now,
	}, nil
}

// ATH returns the base64url-encoded SHA-256 hash of token, the "ath" claim a
// proof carries alongside the access token.
func ATH(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Sign builds a compact DPoP proof for htm/htu. ath is the access token hash
// from ATH, or "" when no token exists yet (enrollment, device-flow token
// polls); nonce is the server nonce once one has been learned.
func (p *Proofer) Sign(htm, htu, ath, nonce string) (string, error) {
	claims := map[string]any{
		"htm": htm,
		"htu": htu,
		"iat": p.now().Unix(),
		"jti": newJTI(),
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	if ath != "" {
		claims["ath"] = ath
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	opts := (&jose.SignerOptions{}).WithType("dpop+jwt")
	opts.EmbedJWK = true
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: p.opaque}, opts)
	if err != nil {
		return "", err
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("dpop: sign: %w", err)
	}
	return jws.CompactSerialize()
}

// newJTI returns a fresh, unique proof identifier.
func newJTI() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		// Extremely rare. Fall back to a time-based identifier.
		return strconv.FormatInt(time.Now().UnixNano(), 10)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

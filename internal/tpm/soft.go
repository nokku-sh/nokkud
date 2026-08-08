package tpm

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	"golang.org/x/crypto/scrypt"

	"github.com/nokku-sh/nokkud/internal/id"
	"github.com/nokku-sh/nokkud/internal/paths"
)

// Software keys are wrapped at rest with a key derived from the machine's
// identity. Copying the state directory to another machine yields nothing
// usable: the wrap key only exists on the machine that created it. This
// protects against stolen or cloned state, not against root on the machine
// itself.
const (
	softScryptN = 1 << 15
	softScryptR = 8
	softScryptP = 1
)

type softSigner struct {
	key *ecdsa.PrivateKey
	pem []byte
}

func openSoft(p paths.Paths, st *state) (Signer, error) {
	if st != nil && len(st.Salt) > 0 && len(st.Nonce) > 0 && len(st.Data) > 0 {
		key, err := unwrapSoftKey(st)
		if err != nil {
			return nil, err
		}
		return &softSigner{key: key, pem: []byte(st.PubKey)}, nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}

	salt := make([]byte, 16)
	nonce := make([]byte, 12)
	if _, err = rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}
	if _, err = rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate nonce: %w", err)
	}
	data, err := wrapSoftKey(der, salt, nonce)
	if err != nil {
		return nil, err
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	st = &state{
		Method: MethodSoft,
		PubKey: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubDER})),
		Salt:   salt,
		Nonce:  nonce,
		Data:   data,
	}
	if err = saveState(p, st); err != nil {
		return nil, err
	}
	return &softSigner{key: key, pem: []byte(st.PubKey)}, nil
}

func (s *softSigner) Method() string {
	return MethodSoft
}

func (s *softSigner) Public() ([]byte, error) {
	return append([]byte(nil), s.pem...), nil
}

func (s *softSigner) Sign(_ context.Context, data []byte) ([]byte, error) {
	digest := sha256.Sum256(data)
	return ecdsa.SignASN1(rand.Reader, s.key, digest[:])
}

func (s *softSigner) Close() error {
	return nil
}

func unwrapSoftKey(st *state) (*ecdsa.PrivateKey, error) {
	plain, err := unwrapSoftData(st.Data, st.Salt, st.Nonce)
	if err != nil {
		return nil, fmt.Errorf(
			"cannot unwrap signing key: %w; the machine identity changed (e.g. after a reinstall or VM clone); re-enroll to create a new key",
			err,
		)
	}
	key, err := x509.ParsePKCS8PrivateKey(plain)
	if err != nil {
		return nil, fmt.Errorf("parse signing key: %w", err)
	}
	priv, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("signing key is not ECDSA")
	}
	return priv, nil
}

func wrapSoftKey(plaintext, salt, nonce []byte) ([]byte, error) {
	key, err := softWrapKey(salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	return gcm.Seal(nil, nonce, plaintext, nil), nil
}

func unwrapSoftData(data, salt, nonce []byte) ([]byte, error) {
	key, err := softWrapKey(salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	return gcm.Open(nil, nonce, data, nil)
}

func softWrapKey(salt []byte) ([]byte, error) {
	return scrypt.Key([]byte(id.MachineID()), salt, softScryptN, softScryptR, softScryptP, 32)
}

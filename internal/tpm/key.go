package tpm

import (
	"crypto"
	"crypto/ecdsa"
	"encoding/asn1"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

// Key is a TPM-resident ECDSA P-256 key implementing [crypto.Signer], used
// for the SSH host identity.
//
// The key is a deterministic primary key. Reopening it with the same salt
// yields the same key pair until the TPM's owner seed changes (TPM clear or
// replacement). The private key never leaves the TPM.
type Key struct {
	tpm    transport.TPM
	closer transport.TPMCloser // nil when the caller owns the transport
	key    *primaryKey
	mu     sync.Mutex
}

// primaryKey is a created primary key handle with the public half cached.
type primaryKey struct {
	pub  *ecdsa.PublicKey
	hnd  tpm2.TPMHandle
	name tpm2.TPM2BName
}

// OpenKey opens the default TPM device and creates the primary key for salt.
// The Key owns the device: Close closes it.
func OpenKey(salt []byte) (*Key, error) {
	dev, err := openTPMDevice()
	if err != nil {
		return nil, err
	}
	k, err := NewKey(dev, salt)
	if err != nil {
		_ = dev.Close()
		return nil, err
	}
	k.closer = dev
	return k, nil
}

// NewKey creates the primary key for salt on an already open TPM. The
// returned Key does not own t.
func NewKey(t transport.TPM, salt []byte) (*Key, error) {
	key, err := createPrimary(t, salt)
	if err != nil {
		return nil, err
	}
	return &Key{tpm: t, key: key}, nil
}

// Public returns the ECDSA public key.
func (k *Key) Public() crypto.PublicKey {
	return k.key.pub
}

// Sign signs a SHA-256 digest and returns the DER-encoded ECDSA signature.
func (k *Key) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf(
			"tpm: unsupported hash %v (key template pins SHA-256)",
			opts.HashFunc(),
		)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	return signECDSA(k.tpm, k.key, digest)
}

// Close flushes the key handle and closes the TPM transport if the Key owns
// it (see OpenKey).
func (k *Key) Close() error {
	return closeKey(k.tpm, k.key.hnd, k.closer)
}

// createPrimary derives the deterministic signing primary key for salt from
// the owner hierarchy seed. Nothing is persisted. The same salt on the same
// TPM reproduces the same key pair.
func createPrimary(t transport.TPM, salt []byte) (*primaryKey, error) {
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: salt}),
			},
		},
		InPublic: tpm2.New2B(eccSignTemplate()),
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("create primary key: %w", err)
	}

	pub, err := publicToECDSA(rsp.OutPublic)
	if err != nil {
		_, _ = tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(t)
		return nil, err
	}

	return &primaryKey{
		pub:  pub,
		hnd:  rsp.ObjectHandle,
		name: rsp.Name,
	}, nil
}

// signECDSA signs digest with the TPM key and returns the DER-encoded ECDSA
// signature.
func signECDSA(t transport.TPM, key *primaryKey, digest []byte) ([]byte, error) {
	rsp, err := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: key.hnd,
			Name:   key.name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digest: tpm2.TPM2BDigest{Buffer: digest},
		// InScheme is left NULL. The key template already pins the ECDSA
		// scheme. The validation ticket must be explicit. A zero ticket
		// has Tag=0, which the TPM rejects as an invalid structure tag.
		Validation: tpm2.TPMTTKHashCheck{
			Tag:       tpm2.TPMSTHashCheck,
			Hierarchy: tpm2.TPMRHNull,
		},
	}.Execute(t)
	if err != nil {
		return nil, fmt.Errorf("tpm sign: %w", err)
	}

	ecc, err := rsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("decode tpm signature: %w", err)
	}
	return asn1MarshalECDSA(ecc.SignatureR.Buffer, ecc.SignatureS.Buffer)
}

func asn1MarshalECDSA(r, s []byte) ([]byte, error) {
	return asn1.Marshal(ecdsaSignature{
		R: new(big.Int).SetBytes(r),
		S: new(big.Int).SetBytes(s),
	})
}

// closeKey flushes the key handle and closes the transport when the caller
// owns it (closer != nil). Shared by the host-key and daemon signing paths.
func closeKey(t transport.TPM, h tpm2.TPMHandle, closer transport.TPMCloser) error {
	var err error
	_, ferr := tpm2.FlushContext{FlushHandle: h}.Execute(t)
	err = errors.Join(err, ferr)
	if closer != nil {
		err = errors.Join(err, closer.Close())
	}
	return err
}

package tpm

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/nokku-sh/nokkud/internal/paths"
)

// signerSalt namespaces the TPM key derivation per application.
//
// Mixed into the primary key derivation so the daemon and the CLI on the
// same machine do not derive the same key pair from the same template. This
// value MUST stay different from nk's signerSalt. "nokku-daemon" here,
// "nokku-cli" there. Do not align them.
var signerSalt = []byte("nokku-daemon")

// eccSignTemplate returns the deterministic ECC P-256 signing template.
// The key derives from the owner seed, the template, and signerSalt, so the
// same public key returns on every boot without storing anything. The private
// key exists only inside the TPM.
func eccSignTemplate() tpm2.TPMTPublic {
	return tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgECC,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			NoDA:                true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCParms{
				Scheme: tpm2.TPMTECCScheme{
					Scheme: tpm2.TPMAlgECDSA,
					Details: tpm2.NewTPMUAsymScheme(
						tpm2.TPMAlgECDSA,
						&tpm2.TPMSSigSchemeECDSA{HashAlg: tpm2.TPMAlgSHA256},
					),
				},
				CurveID: tpm2.TPMECCNistP256,
			},
		),
		Unique: tpm2.NewTPMUPublicID(
			tpm2.TPMAlgECC,
			&tpm2.TPMSECCPoint{
				X: tpm2.TPM2BECCParameter{Buffer: []byte{}},
				Y: tpm2.TPM2BECCParameter{Buffer: []byte{}},
			},
		),
	}
}

// ecdsaSignature mirrors crypto/ecdsa's internal type for DER encoding.
type ecdsaSignature struct {
	R, S *big.Int
}

type tpmSigner struct {
	tpm    transport.TPM
	closer transport.TPMCloser
	key    *primaryKey
	pem    []byte
	mu     sync.Mutex
}

func openTPM(p paths.Paths, st *state) (Signer, error) {
	rwr, err := openTPMDevice()
	if err != nil {
		return nil, err
	}

	s, err := createTPMSigner(rwr)
	if err != nil {
		_ = rwr.Close()
		return nil, err
	}
	s.closer = rwr

	pub, err := s.Public()
	if err != nil {
		_ = s.Close()
		return nil, err
	}

	cur := string(pub)
	if st != nil && st.PubKey != "" && st.PubKey != cur {
		_ = s.Close()
		return nil, errors.New(
			"TPM identity changed since enrollment (TPM was cleared or replaced); re-enroll to register the new key",
		)
	}
	if st == nil || st.PubKey != cur {
		if err = saveState(p, &state{Method: MethodTPM, PubKey: cur}); err != nil {
			_ = s.Close()
			return nil, err
		}
	}
	return s, nil
}

// createTPMSigner creates the signing primary key on r and returns a signer
// for it. The returned signer does not own r.
func createTPMSigner(r transport.TPM) (*tpmSigner, error) {
	key, err := createPrimary(r, signerSalt)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(key.pub)
	if err != nil {
		_, _ = tpm2.FlushContext{FlushHandle: key.hnd}.Execute(r)
		return nil, err
	}

	return &tpmSigner{
		tpm: r,
		key: key,
		pem: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}),
	}, nil
}

func (s *tpmSigner) Method() string {
	return MethodTPM
}

func (s *tpmSigner) Public() ([]byte, error) {
	return append([]byte(nil), s.pem...), nil
}

func (s *tpmSigner) Sign(_ context.Context, data []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	digest := sha256.Sum256(data)
	return signECDSA(s.tpm, s.key, digest[:])
}

// CryptoSigner exposes the TPM key as a [crypto.Signer] for DPoP proofs.
func (s *tpmSigner) CryptoSigner() crypto.Signer {
	return &tpmCryptoSigner{signer: s}
}

// tpmCryptoSigner adapts a tpmSigner to [crypto.Signer]: go-jose hashes the
// signing input and calls Sign with the digest, and the TPM template pins
// SHA-256, so the digest is signed directly without double-hashing.
type tpmCryptoSigner struct {
	signer *tpmSigner
}

func (s *tpmCryptoSigner) Public() crypto.PublicKey { return s.signer.key.pub }

func (s *tpmCryptoSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts.HashFunc() != crypto.SHA256 {
		return nil, fmt.Errorf("tpm: unsupported hash %v (key pins SHA-256)", opts.HashFunc())
	}
	s.signer.mu.Lock()
	defer s.signer.mu.Unlock()
	return signECDSA(s.signer.tpm, s.signer.key, digest)
}

func (s *tpmSigner) Close() error {
	var err error
	_, ferr := tpm2.FlushContext{FlushHandle: s.key.hnd}.Execute(s.tpm)
	err = errors.Join(err, ferr)
	if s.closer != nil {
		err = errors.Join(err, s.closer.Close())
	}
	return err
}

func publicToECDSA(pub tpm2.TPM2BPublic) (*ecdsa.PublicKey, error) {
	tp, err := pub.Contents()
	if err != nil {
		return nil, fmt.Errorf("decode public key: %w", err)
	}
	if tp.Type != tpm2.TPMAlgECC {
		return nil, errors.New("TPM key is not ECC")
	}
	point, err := tp.Unique.ECC()
	if err != nil {
		return nil, fmt.Errorf("decode ECC point: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(point.X.Buffer),
		Y:     new(big.Int).SetBytes(point.Y.Buffer),
	}, nil
}

package tpm

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"

	"github.com/nokku-sh/nokkud/internal/paths"
)

// signerSalt namespaces the TPM key derivation per application.
//
// The salt is mixed into the primary key derivation, so it keeps the daemon
// and the CLI on the same machine from deriving the same key pair while both
// use the same SHA-256 template. This value MUST stay different from nk's
// signerSalt: this daemon uses "nokku-daemon", the CLI uses "nokku-cli". Do
// not align them.
var signerSalt = []byte("nokku-daemon")

// eccSignTemplate returns the deterministic ECC P-256 signing template. The
// key is derived from the owner hierarchy seed, the template and signerSalt,
// so the same public key is returned on every boot without storing anything:
// the private key exists only inside the TPM.
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
	hnd    tpm2.TPMHandle
	name   tpm2.TPM2BName
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

// createTPMSigner creates the signing primary key on r and returns
// a signer for it. The returned signer does not own r.
func createTPMSigner(r transport.TPM) (*tpmSigner, error) {
	tmpl := eccSignTemplate()
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InSensitive: tpm2.TPM2BSensitiveCreate{
			Sensitive: &tpm2.TPMSSensitiveCreate{
				Data: tpm2.NewTPMUSensitiveCreate(&tpm2.TPM2BSensitiveData{Buffer: signerSalt}),
			},
		},
		InPublic: tpm2.New2B(tmpl),
	}.Execute(r)
	if err != nil {
		return nil, fmt.Errorf("create primary key: %w", err)
	}

	pub, err := publicToECDSA(rsp.OutPublic)
	if err != nil {
		_, _ = tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(r)
		return nil, err
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}

	return &tpmSigner{
		tpm:  r,
		hnd:  rsp.ObjectHandle,
		name: rsp.Name,
		pem:  pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}),
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
	rsp, err := tpm2.Sign{
		KeyHandle: tpm2.AuthHandle{
			Handle: s.hnd,
			Name:   s.name,
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digest: tpm2.TPM2BDigest{Buffer: digest[:]},
		// InScheme is left NULL: the key template already pins the ECDSA
		// scheme. The validation ticket must be explicit: a zero ticket
		// has Tag=0, which the TPM rejects as an invalid structure tag.
		Validation: tpm2.TPMTTKHashCheck{
			Tag:       tpm2.TPMSTHashCheck,
			Hierarchy: tpm2.TPMRHNull,
		},
	}.Execute(s.tpm)
	if err != nil {
		return nil, fmt.Errorf("tpm sign: %w", err)
	}

	ecc, err := rsp.Signature.Signature.ECDSA()
	if err != nil {
		return nil, fmt.Errorf("decode tpm signature: %w", err)
	}
	return asn1.Marshal(ecdsaSignature{
		R: new(big.Int).SetBytes(ecc.SignatureR.Buffer),
		S: new(big.Int).SetBytes(ecc.SignatureS.Buffer),
	})
}

func (s *tpmSigner) Close() error {
	var err error
	_, ferr := tpm2.FlushContext{FlushHandle: s.hnd}.Execute(s.tpm)
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

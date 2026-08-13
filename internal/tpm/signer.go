// Package tpm provides the machine's signing identity. ECDSA P-256
// signatures over request challenges, TPM-backed when available, else a
// software key wrapped to the machine identity.
package tpm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/nokku-sh/nokkud/internal/paths"
	"github.com/nokku-sh/nokkud/internal/util"
)

const (
	// MethodTPM identifies a TPM-backed signing key.
	MethodTPM = "tpm"
	// MethodSoft identifies a software signing key wrapped to the machine.
	MethodSoft = "soft"
)

// Signer signs request challenges with a machine-bound key.
type Signer interface {
	// Method returns the signing method: MethodTPM or MethodSoft.
	Method() string
	// Public returns the PEM-encoded PKIX public key.
	Public() ([]byte, error)
	// Sign signs data with SHA-256 and returns a DER-encoded ECDSA signature.
	Sign(ctx context.Context, data []byte) ([]byte, error)
	// Close releases the underlying key material.
	Close() error
}

// state is the on-disk representation of a signer. Only public material is
// stored for TPM keys. Software keys additionally carry their wrapped
// private key.
type state struct {
	Method string `json:"method"`
	PubKey string `json:"pubkey"`
	Salt   []byte `json:"salt,omitempty"`
	Nonce  []byte `json:"nonce,omitempty"`
	Data   []byte `json:"data,omitempty"`
}

// errNoState signals that no signer state exists yet on this machine.
var errNoState = errors.New("no signer state")

// New loads or creates the machine's signing identity: TPM when
// available, else a machine-wrapped software key (error if requireTPM).
func New(p paths.Paths, requireTPM bool) (Signer, error) {
	st, err := loadState(p)
	if err != nil && !errors.Is(err, errNoState) {
		return nil, err
	}

	if st != nil {
		switch st.Method {
		case MethodTPM:
			s, tpmErr := openTPM(p, st)
			if tpmErr != nil {
				return nil, fmt.Errorf("tpm signer: %w", tpmErr)
			}
			return s, nil
		case MethodSoft:
			if requireTPM {
				return nil, errors.New(
					"daemon is enrolled with a software key; re-enroll with --require-tpm to require a TPM",
				)
			}
			s, softErr := openSoft(p, st)
			if softErr != nil {
				return nil, fmt.Errorf("software signer: %w", softErr)
			}
			return s, nil
		default:
			return nil, fmt.Errorf("unknown signer method %q", st.Method)
		}
	}

	s, err := openTPM(p, nil)
	if err == nil {
		return s, nil
	}
	if requireTPM {
		return nil, fmt.Errorf("no TPM available: %w", err)
	}
	s, err = openSoft(p, nil)
	if err != nil {
		return nil, fmt.Errorf("software signer: %w", err)
	}
	return s, nil
}

func loadState(p paths.Paths) (*state, error) {
	data, err := os.ReadFile(p.SignerStateFile())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, errNoState
		}
		return nil, fmt.Errorf("read signer state: %w", err)
	}
	var st state
	if err = json.Unmarshal(data, &st); err != nil {
		return nil, fmt.Errorf("parse signer state: %w", err)
	}
	return &st, nil
}

func saveState(p paths.Paths, st *state) error {
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("serialize signer state: %w", err)
	}
	if err = util.WriteIfChanged(p.SignerStateFile(), data, 0o600); err != nil {
		return fmt.Errorf("write signer state: %w", err)
	}
	return nil
}

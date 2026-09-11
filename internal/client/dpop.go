package client

import (
	"github.com/nokku-sh/mon/dpop"
	"github.com/nokku-sh/mon/tpm"

	"github.com/nokku-sh/nokkud/internal/paths"
)

var signerSalt = []byte("nokku-daemon")

func newProofer(requireTPM bool) (*dpop.Proofer, error) {
	signer, err := tpm.NewSigner(tpm.SignerOptions{
		Salt:             signerSalt,
		StatePath:        paths.SignerStateFile(),
		RequireTPM:       requireTPM,
		OnIdentityChange: tpm.FailOnIdentityChange,
	})
	if err != nil {
		return nil, err
	}
	return dpop.NewProofer(signer, dpop.ProoferOptions{})
}

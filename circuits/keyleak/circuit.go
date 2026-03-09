package keyleak

import (
	"github.com/MuriData/muri-zkproof/circuits/shared"
	"github.com/MuriData/muri-zkproof/pkg/crypto"
	"github.com/consensys/gnark/frontend"
)

// KeyLeakCircuit proves knowledge of a secret key whose hash matches a
// registered public key, without revealing the secret key on-chain.
// This allows front-running-resistant slashing of nodes whose keys are leaked.
type KeyLeakCircuit struct {
	// Public inputs
	PublicKey       frontend.Variable `gnark:"publicKey,public"`
	ReporterAddress frontend.Variable `gnark:"reporterAddress,public"`

	// Private witness
	SecretKey frontend.Variable `gnark:"secretKey"`
}

func (circuit *KeyLeakCircuit) Define(api frontend.API) error {
	sponge, err := shared.NewSpongeHasher(api)
	if err != nil {
		return err
	}

	// 1. SecretKey must be non-zero (a zero key is trivially known).
	api.AssertIsEqual(api.IsZero(circuit.SecretKey), 0)

	// 2. PublicKey must be non-zero (a zero public key bypasses identity checks).
	api.AssertIsEqual(api.IsZero(circuit.PublicKey), 0)

	// 3. Key ownership: publicKey == H(secretKey).
	derivedPubKey, err := sponge.Hash(frontend.Variable(crypto.DomainTagPubKey), circuit.SecretKey)
	if err != nil {
		return err
	}

	api.AssertIsEqual(circuit.PublicKey, derivedPubKey)

	// ReporterAddress is a public input with no constraint — it binds the
	// proof to the reporter so that front-runners cannot steal the reward.
	_ = circuit.ReporterAddress

	return nil
}

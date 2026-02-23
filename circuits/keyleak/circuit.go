package keyleak

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/permutation/poseidon2"
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
	// Poseidon2 with same parameters as the PoI circuit.
	p, err := poseidon2.NewPoseidon2FromParameters(api, 2, 6, 50)
	if err != nil {
		return err
	}

	// 1. SecretKey must be non-zero (a zero key is trivially known).
	api.AssertIsEqual(api.IsZero(circuit.SecretKey), 0)

	// 2. PublicKey must be non-zero (a zero public key bypasses identity checks).
	api.AssertIsEqual(api.IsZero(circuit.PublicKey), 0)

	// 3. Key ownership: publicKey == H(secretKey).
	keyHasher := hash.NewMerkleDamgardHasher(api, p, 0)
	keyHasher.Write(circuit.SecretKey)
	derivedPubKey := keyHasher.Sum()

	api.AssertIsEqual(circuit.PublicKey, derivedPubKey)

	// ReporterAddress is a public input with no constraint — it binds the
	// proof to the reporter so that front-runners cannot steal the reward.
	_ = circuit.ReporterAddress

	return nil
}

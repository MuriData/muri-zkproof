package crypto

import (
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

// Poseidon2 sponge parameters: width=3 (rate=2, capacity=1).
const (
	SpongeWidth        = 3
	SpongeRate         = 2
	SpongeFullRounds   = 6
	SpongePartRounds   = 50
)

// spongePerm is the package-level permutation instance for the sponge.
var spongePerm *poseidon2.Permutation

func init() {
	spongePerm = poseidon2.NewPermutation(SpongeWidth, SpongeFullRounds, SpongePartRounds)
}

// SpongeHash computes a Poseidon2 sponge hash with domain separation.
//
// The domain tag is placed in the capacity lane (state[2]) before any
// absorption. Inputs are absorbed in rate-sized blocks (2 elements per
// permutation call). An odd final input is absorbed alone into state[0]
// before permuting.
//
// Returns state[0] after all absorptions (squeeze).
func SpongeHash(domainTag int, inputs []fr.Element) fr.Element {
	var state [SpongeWidth]fr.Element
	// Domain separation: capacity lane.
	state[SpongeRate].SetInt64(int64(domainTag))

	for i := 0; i < len(inputs); i += SpongeRate {
		state[0].Add(&state[0], &inputs[i])
		if i+1 < len(inputs) {
			state[1].Add(&state[1], &inputs[i+1])
		}
		spongePerm.Permutation(state[:])
	}

	// Empty input: permute once so the output depends on the domain tag.
	if len(inputs) == 0 {
		spongePerm.Permutation(state[:])
	}

	return state[0]
}

// SpongeHashBigInt is a convenience wrapper over SpongeHash that accepts
// and returns *big.Int values.
func SpongeHashBigInt(domainTag int, inputs ...*big.Int) *big.Int {
	elems := make([]fr.Element, len(inputs))
	for i, v := range inputs {
		elems[i].SetBigInt(v)
	}
	result := SpongeHash(domainTag, elems)
	out := new(big.Int)
	result.BigInt(out)
	return out
}

// SpongeHashFr is a convenience variadic wrapper over SpongeHash.
func SpongeHashFr(domainTag int, inputs ...fr.Element) fr.Element {
	return SpongeHash(domainTag, inputs)
}

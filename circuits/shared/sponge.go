package shared

import (
	"github.com/MuriData/muri-zkproof/pkg/crypto"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/permutation/poseidon2"
)

// SpongeHasher provides Poseidon2 sponge hashing inside gnark circuits.
//
// It uses width=3 (rate=2, capacity=1) with domain separation via the
// capacity lane. Each Hash call is independent — no state carries over
// between calls.
type SpongeHasher struct {
	api  frontend.API
	perm *poseidon2.Permutation
}

// NewSpongeHasher creates a circuit sponge hasher. The underlying
// Poseidon2 permutation uses the same parameters as the native Go
// sponge (width=3, 6 full rounds, 50 partial rounds).
func NewSpongeHasher(api frontend.API) (*SpongeHasher, error) {
	perm, err := poseidon2.NewPoseidon2FromParameters(
		api,
		crypto.SpongeWidth,
		crypto.SpongeFullRounds,
		crypto.SpongePartRounds,
	)
	if err != nil {
		return nil, err
	}
	return &SpongeHasher{api: api, perm: perm}, nil
}

// Hash computes Poseidon2 sponge hash with domain separation.
//
// The domainTag is placed in the capacity lane (state[2]). Inputs are
// absorbed in rate-sized blocks (2 elements per permutation call).
// Returns state[0] after all absorptions.
func (s *SpongeHasher) Hash(domainTag frontend.Variable, inputs ...frontend.Variable) (frontend.Variable, error) {
	state := [crypto.SpongeWidth]frontend.Variable{
		frontend.Variable(0),
		frontend.Variable(0),
		domainTag,
	}

	for i := 0; i < len(inputs); i += crypto.SpongeRate {
		state[0] = s.api.Add(state[0], inputs[i])
		if i+1 < len(inputs) {
			state[1] = s.api.Add(state[1], inputs[i+1])
		}
		if err := s.perm.Permutation(state[:]); err != nil {
			return nil, err
		}
	}

	// Empty input: permute once so output depends on the domain tag.
	if len(inputs) == 0 {
		if err := s.perm.Permutation(state[:]); err != nil {
			return nil, err
		}
	}

	return state[0], nil
}

package fsp

import (
	"github.com/MuriData/muri-zkproof/circuits/shared"
	"github.com/MuriData/muri-zkproof/pkg/crypto"
	"github.com/consensys/gnark/frontend"
)

// BoundaryMerkleProof is a lightweight sub-circuit for boundary validation.
// It takes a pre-computed LeafHash (no byte array) and verifies a depth-20
// Merkle path, returning the computed root for the caller to check.
type BoundaryMerkleProof struct {
	LeafHash   frontend.Variable                `gnark:"leafHash"`
	ProofPath  [MaxTreeDepth]frontend.Variable   `gnark:"proofPath"`
	Directions [MaxTreeDepth]frontend.Variable   `gnark:"directions"`
}

// ComputeRoot hashes through all MaxTreeDepth levels and returns the computed
// root. The caller is responsible for comparing it to the expected root (with
// optional guarding for the isFull edge case).
func (bp *BoundaryMerkleProof) ComputeRoot(api frontend.API, sponge *shared.SpongeHasher) (frontend.Variable, error) {
	currentHash := bp.LeafHash

	for i := 0; i < MaxTreeDepth; i++ {
		sibling := bp.ProofPath[i]
		direction := bp.Directions[i]

		leftHash := api.Select(direction, sibling, currentHash)
		rightHash := api.Select(direction, currentHash, sibling)
		var err error
		currentHash, err = sponge.Hash(frontend.Variable(crypto.DomainTagNode), leftHash, rightHash)
		if err != nil {
			return nil, err
		}
	}

	return currentHash, nil
}

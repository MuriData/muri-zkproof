package fsp

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/permutation/poseidon2"
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
func (bp *BoundaryMerkleProof) ComputeRoot(api frontend.API) (frontend.Variable, error) {
	p, err := poseidon2.NewPoseidon2FromParameters(api, 2, 6, 50)
	if err != nil {
		return nil, err
	}
	hasher := hash.NewMerkleDamgardHasher(api, p, 0)

	currentHash := bp.LeafHash

	for i := 0; i < MaxTreeDepth; i++ {
		sibling := bp.ProofPath[i]
		direction := bp.Directions[i]

		hasher.Reset()
		leftHash := api.Select(direction, sibling, currentHash)
		rightHash := api.Select(direction, currentHash, sibling)
		hasher.Write(leftHash, rightHash)
		currentHash = hasher.Sum()
	}

	return currentHash, nil
}

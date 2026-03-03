package shared

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/permutation/poseidon2"
)

const (
	Depth10 = 10
	Depth20 = 20
	Depth30 = 30
)

// MerkleProof10 verifies a depth-10 Merkle path (slot tree level).
type MerkleProof10 struct {
	LeafHash   frontend.Variable              `gnark:"leafHash"`
	ProofPath  [Depth10]frontend.Variable     `gnark:"proofPath"`
	Directions [Depth10]frontend.Variable     `gnark:"directions"`
}

// ComputeRoot hashes through all 10 levels and returns the computed root.
func (mp *MerkleProof10) ComputeRoot(api frontend.API) (frontend.Variable, error) {
	return computeMerkleRoot(api, mp.LeafHash, mp.ProofPath[:], mp.Directions[:])
}

// MerkleProof20 verifies a depth-20 Merkle path (file subtree level).
type MerkleProof20 struct {
	LeafHash   frontend.Variable              `gnark:"leafHash"`
	ProofPath  [Depth20]frontend.Variable     `gnark:"proofPath"`
	Directions [Depth20]frontend.Variable     `gnark:"directions"`
}

// ComputeRoot hashes through all 20 levels and returns the computed root.
func (mp *MerkleProof20) ComputeRoot(api frontend.API) (frontend.Variable, error) {
	return computeMerkleRoot(api, mp.LeafHash, mp.ProofPath[:], mp.Directions[:])
}

// MerkleProof30 verifies a depth-30 Merkle path (combined archive tree).
type MerkleProof30 struct {
	LeafHash   frontend.Variable              `gnark:"leafHash"`
	ProofPath  [Depth30]frontend.Variable     `gnark:"proofPath"`
	Directions [Depth30]frontend.Variable     `gnark:"directions"`
}

// ComputeRoot hashes through all 30 levels and returns the computed root.
func (mp *MerkleProof30) ComputeRoot(api frontend.API) (frontend.Variable, error) {
	return computeMerkleRoot(api, mp.LeafHash, mp.ProofPath[:], mp.Directions[:])
}

// computeMerkleRoot is the shared Merkle root computation using Poseidon2.
func computeMerkleRoot(api frontend.API, leafHash frontend.Variable, proofPath []frontend.Variable, directions []frontend.Variable) (frontend.Variable, error) {
	p, err := poseidon2.NewPoseidon2FromParameters(api, 2, 6, 50)
	if err != nil {
		return nil, err
	}
	hasher := hash.NewMerkleDamgardHasher(api, p, 0)

	currentHash := leafHash
	for i := 0; i < len(proofPath); i++ {
		sibling := proofPath[i]
		direction := directions[i]

		hasher.Reset()
		leftHash := api.Select(direction, sibling, currentHash)
		rightHash := api.Select(direction, currentHash, sibling)
		hasher.Write(leftHash, rightHash)
		currentHash = hasher.Sum()
	}

	return currentHash, nil
}

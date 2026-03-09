package poi

import (
	"github.com/MuriData/muri-zkproof/circuits/shared"
	"github.com/MuriData/muri-zkproof/pkg/crypto"
	"github.com/consensys/gnark/frontend"
)

// MerkleProofCircuit verifies a Merkle proof in a fixed depth-20 sparse tree.
// All MaxTreeDepth levels are always active (no skip logic).
type MerkleProofCircuit struct {
	// Public inputs
	RootHash frontend.Variable `gnark:"rootHash"`

	// Private inputs
	LeafValue  frontend.Variable                    `gnark:"leafValue"`  // The leaf hash we're proving membership of
	ProofPath  [MaxTreeDepth]frontend.Variable `gnark:"proofPath"`  // Sibling hashes along the path to root
	Directions [MaxTreeDepth]frontend.Variable `gnark:"directions"` // 0 = sibling on right, 1 = sibling on left
}

// Define implements the circuit logic for Merkle proof verification.
// All 20 levels are always hashed — no conditional skip.
func (circuit *MerkleProofCircuit) Define(api frontend.API, sponge *shared.SpongeHasher) error {
	currentHash := circuit.LeafValue

	for i := 0; i < MaxTreeDepth; i++ {
		sibling := circuit.ProofPath[i]
		direction := circuit.Directions[i]

		leftHash := api.Select(direction, sibling, currentHash)
		rightHash := api.Select(direction, currentHash, sibling)
		var err error
		currentHash, err = sponge.Hash(frontend.Variable(crypto.DomainTagNode), leftHash, rightHash)
		if err != nil {
			return err
		}
	}

	api.AssertIsEqual(currentHash, circuit.RootHash)

	return nil
}

// BoundaryMerkleProof is a lightweight sub-circuit for boundary validation.
// It takes a pre-computed LeafHash (no byte array) and verifies a depth-20
// Merkle path, returning the computed root for the caller to check.
type BoundaryMerkleProof struct {
	LeafHash   frontend.Variable                    `gnark:"leafHash"`
	ProofPath  [MaxTreeDepth]frontend.Variable `gnark:"proofPath"`
	Directions [MaxTreeDepth]frontend.Variable `gnark:"directions"`
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

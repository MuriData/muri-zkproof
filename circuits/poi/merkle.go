package poi

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/permutation/poseidon2"
)

// MerkleProofCircuit represents a circuit for verifying Merkle proofs.
type MerkleProofCircuit struct {
	// Public inputs
	RootHash frontend.Variable `gnark:"rootHash"`

	// Private inputs
	LeafValue  frontend.Variable                    `gnark:"leafValue"`  // The actual data value we're proving membership of
	ProofPath  [MaxTreeDepth]frontend.Variable `gnark:"proofPath"`  // Sibling hashes along the path to root
	Directions [MaxTreeDepth]frontend.Variable `gnark:"directions"` // 0 = sibling on right, 1 = sibling on left
}

// Define implements the circuit logic for Merkle proof verification.
func (circuit *MerkleProofCircuit) Define(api frontend.API) error {
	// Initialize Poseidon2 hasher
	p, err := poseidon2.NewPoseidon2FromParameters(api, 2, 6, 50)
	if err != nil {
		return err
	}
	hasher := hash.NewMerkleDamgardHasher(api, p, 0)

	currentHash := circuit.LeafValue

	// Step 2: Verify the proof path
	// We'll process exactly MaxTreeDepth levels; padding nodes have sibling=0 so they don't alter the hash or constraints.
	for i := 0; i < MaxTreeDepth; i++ {
		// Get the sibling hash for this level
		sibling := circuit.ProofPath[i]
		direction := circuit.Directions[i]

		// If sibling is zero, it means we've reached past-proof padding and we
		// should NOT update the running hash any further.
		siblingIsZero := api.IsZero(sibling)

		// Hash current node with sibling (only meaningful if sibling != 0)
		// Convention: direction == 0  → sibling on the RIGHT (current node is LEFT)
		//              direction == 1  → sibling on the LEFT  (current node is RIGHT)
		hasher.Reset()
		leftHash := api.Select(direction, sibling, currentHash)
		rightHash := api.Select(direction, currentHash, sibling)
		hasher.Write(leftHash, rightHash)
		newHash := hasher.Sum()

		// Update the accumulator only when sibling != 0
		currentHash = api.Select(siblingIsZero, currentHash, newHash)
	}

	// Step 3: Verify that the computed root matches the expected root
	api.AssertIsEqual(currentHash, circuit.RootHash)

	return nil
}

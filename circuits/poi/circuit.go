package poi

import (
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/permutation/poseidon2"
)

type PoICircuit struct {
	// Publics
	Commitment frontend.Variable `gnark:"commitment,public"`
	Randomness frontend.Variable `gnark:"randomness,public"`
	PublicKey  frontend.Variable `gnark:"publicKey,public"`
	RootHash   frontend.Variable `gnark:"rootHash,public"`

	// Privates
	SecretKey    frontend.Variable                           `gnark:"secretKey"`
	Bytes        [OpeningsCount][NumChunks]frontend.Variable `gnark:"bytes"`
	MerkleProofs [OpeningsCount]MerkleProofCircuit           `gnark:"merkleProofs"`
}

func (circuit *PoICircuit) Define(api frontend.API) error {
	p, err := poseidon2.NewPoseidon2FromParameters(api, 2, 6, 50)
	if err != nil {
		return err
	}

	// 1. Key ownership: publicKey == H(secretKey), both non-zero.
	api.AssertIsEqual(api.IsZero(circuit.SecretKey), 0)
	api.AssertIsEqual(api.IsZero(circuit.PublicKey), 0)

	keyHasher := hash.NewMerkleDamgardHasher(api, p, 0)
	keyHasher.Write(circuit.SecretKey)
	derivedPubKey := keyHasher.Sum()
	keyHasher.Reset()

	api.AssertIsEqual(circuit.PublicKey, derivedPubKey)

	// 2. Randomness decomposition (once for all openings).
	api.AssertIsEqual(api.IsZero(circuit.Randomness), 0)
	randBitsFull := api.ToBinary(circuit.Randomness, api.Compiler().FieldBitLen())

	// 3. Per-opening: leaf hash, Merkle link, direction enforcement, monotonicity, verify.
	var leafHashes [OpeningsCount]frontend.Variable

	for k := 0; k < OpeningsCount; k++ {
		// 3a. Compute leaf hash from raw data chunk.
		leafHasher := hash.NewMerkleDamgardHasher(api, p, 0)
		leafHasher.Write(circuit.Bytes[k][:]...)
		leafHashes[k] = leafHasher.Sum()
		leafHasher.Reset()

		// 3b. Link computed leaf hash and public root to the sub-circuit.
		api.AssertIsEqual(circuit.MerkleProofs[k].LeafValue, leafHashes[k])
		api.AssertIsEqual(circuit.MerkleProofs[k].RootHash, circuit.RootHash)

		// 3c. Direction enforcement from bit window [k*MaxTreeDepth .. (k+1)*MaxTreeDepth-1].
		bitOffset := k * MaxTreeDepth
		for j := 0; j < MaxTreeDepth; j++ {
			sibling := circuit.MerkleProofs[k].ProofPath[j]
			direction := circuit.MerkleProofs[k].Directions[j]

			isActive := api.Sub(1, api.IsZero(sibling))
			expectedDir := api.Sub(1, randBitsFull[bitOffset+j])
			diff := api.Sub(direction, expectedDir)
			api.AssertIsEqual(api.Mul(diff, isActive), 0)
		}

		// 3d. Monotonicity: once a zero sibling appears, all subsequent must be zero.
		prevActive := frontend.Variable(1)
		for j := 0; j < MaxTreeDepth; j++ {
			siblingIsZero := api.IsZero(circuit.MerkleProofs[k].ProofPath[j])
			viol := api.Mul(api.Sub(1, prevActive), api.Sub(1, siblingIsZero))
			api.AssertIsEqual(viol, 0)
			prevActive = api.Mul(prevActive, api.Sub(1, siblingIsZero))
		}

		// 3e. Verify the Merkle proof.
		circuit.MerkleProofs[k].Define(api)
	}

	// 4. Minimum depth: at least one hashing level (depth >= 1) on the first opening.
	api.AssertIsEqual(api.IsZero(circuit.MerkleProofs[0].ProofPath[0]), 0)

	// 5. Aggregate message: aggMsg = H(leafHash[0], ..., leafHash[7], randomness).
	aggHasher := hash.NewMerkleDamgardHasher(api, p, 0)
	for k := 0; k < OpeningsCount; k++ {
		aggHasher.Write(leafHashes[k])
	}
	aggHasher.Write(circuit.Randomness)
	aggMsg := aggHasher.Sum()
	aggHasher.Reset()

	// 6. VRF commitment: commitment = H(secretKey, aggMsg, randomness, publicKey).
	vrfHasher := hash.NewMerkleDamgardHasher(api, p, 0)
	vrfHasher.Write(circuit.SecretKey)
	vrfHasher.Write(aggMsg)
	vrfHasher.Write(circuit.Randomness)
	vrfHasher.Write(circuit.PublicKey)
	derivedCommitment := vrfHasher.Sum()
	vrfHasher.Reset()

	api.AssertIsEqual(circuit.Commitment, derivedCommitment)

	return nil
}

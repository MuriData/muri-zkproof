package poi

import (
	"math/big"

	"github.com/MuriData/muri-zkproof/pkg/crypto"
	"github.com/MuriData/muri-zkproof/pkg/merkle"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/permutation/poseidon2"
)

// zeroLeafHash is the domain-separated hash for padding leaves, computed once
// at package init. It is used as a circuit constant.
var zeroLeafHash *big.Int

// zeroSubtreeHashes[j] is the hash of an all-zero subtree of depth j.
// zeroSubtreeHashes[0] = zeroLeafHash, zeroSubtreeHashes[j] = H(zh[j-1], zh[j-1]).
// Used by the FSP-style sibling zero-checks on the boundary proof.
var zeroSubtreeHashes [MaxTreeDepth]*big.Int

func init() {
	zeroLeafHash = crypto.ComputeZeroLeafHash(ElementSize, NumChunks)
	zh := merkle.PrecomputeZeroHashes(MaxTreeDepth, zeroLeafHash)
	for i := 0; i < MaxTreeDepth; i++ {
		zeroSubtreeHashes[i] = zh[i]
	}
}

type PoICircuit struct {
	// Public inputs (4, unchanged)
	Commitment frontend.Variable `gnark:"commitment,public"`
	Randomness frontend.Variable `gnark:"randomness,public"`
	PublicKey  frontend.Variable `gnark:"publicKey,public"`
	RootHash   frontend.Variable `gnark:"rootHash,public"`

	// Private inputs
	SecretKey    frontend.Variable                           `gnark:"secretKey"`
	NumLeaves    frontend.Variable                           `gnark:"numLeaves"`
	Bytes        [OpeningsCount][NumChunks]frontend.Variable `gnark:"bytes"`
	MerkleProofs [OpeningsCount]MerkleProofCircuit           `gnark:"merkleProofs"`
	Quotients    [OpeningsCount]frontend.Variable            `gnark:"quotients"`
	LeafIndices  [OpeningsCount]frontend.Variable            `gnark:"leafIndices"`

	// Boundary proof: single Merkle proof of leaf at numLeaves-1.
	// Replaces the old two-proof approach with FSP-style sibling zero-checks.
	BoundaryProof BoundaryMerkleProof `gnark:"boundaryProof"`
}

func (circuit *PoICircuit) Define(api frontend.API) error {
	p, err := poseidon2.NewPoseidon2FromParameters(api, 2, 6, 50)
	if err != nil {
		return err
	}

	// ---------------------------------------------------------------
	// 1. Key ownership: publicKey == H(secretKey), both non-zero.
	// ---------------------------------------------------------------
	api.AssertIsEqual(api.IsZero(circuit.SecretKey), 0)
	api.AssertIsEqual(api.IsZero(circuit.PublicKey), 0)

	keyHasher := hash.NewMerkleDamgardHasher(api, p, 0)
	keyHasher.Write(circuit.SecretKey)
	derivedPubKey := keyHasher.Sum()
	keyHasher.Reset()
	api.AssertIsEqual(circuit.PublicKey, derivedPubKey)

	// ---------------------------------------------------------------
	// 2. Randomness decomposition (once for all openings).
	// ---------------------------------------------------------------
	api.AssertIsEqual(api.IsZero(circuit.Randomness), 0)
	randBitsFull := api.ToBinary(circuit.Randomness, api.Compiler().FieldBitLen())

	// ---------------------------------------------------------------
	// 3. NumLeaves validation + FSP-style boundary proof.
	//    Single Merkle proof of leaf[numLeaves-1] with sibling zero-checks.
	// ---------------------------------------------------------------
	// Range check: numLeaves in [1, TotalLeaves].
	api.AssertIsEqual(api.IsZero(circuit.NumLeaves), 0)

	lastIdx := api.Sub(circuit.NumLeaves, 1)
	lastBits := api.ToBinary(lastIdx, MaxTreeDepth)

	// Direction bits must match the binary decomposition of lastIdx.
	for j := 0; j < MaxTreeDepth; j++ {
		api.AssertIsEqual(circuit.BoundaryProof.Directions[j], lastBits[j])
	}

	// Leaf must be non-zero (real data, not padding).
	zeroLeafConst := frontend.Variable(zeroLeafHash)
	api.AssertIsEqual(api.IsZero(api.Sub(circuit.BoundaryProof.LeafHash, zeroLeafConst)), 0)

	// Zero-sibling check: at each level where last is a left child
	// (bit = 0), the sibling must equal the zero subtree hash for
	// that level. This proves no real chunk exists beyond lastIdx.
	// When numLeaves == TotalLeaves, all bits are 1 (right child at
	// every level), so no zero-sibling checks are enforced.
	for j := 0; j < MaxTreeDepth; j++ {
		zhConst := frontend.Variable(zeroSubtreeHashes[j])
		isLeftChild := api.Sub(1, lastBits[j]) // 1 if left child, 0 if right
		diff := api.Sub(circuit.BoundaryProof.ProofPath[j], zhConst)
		api.AssertIsEqual(api.Mul(isLeftChild, diff), 0)
	}

	// Verify the proof path reconstructs the claimed root.
	boundaryRoot, err := circuit.BoundaryProof.ComputeRoot(api)
	if err != nil {
		return err
	}
	api.AssertIsEqual(boundaryRoot, circuit.RootHash)

	// ---------------------------------------------------------------
	// 4. Bounded comparator for leafIndex < numLeaves checks.
	// ---------------------------------------------------------------
	// Max |a - b| is TotalLeaves (when leafIndex=0, numLeaves=TotalLeaves).
	comparator := cmp.NewBoundedComparator(api, new(big.Int).SetInt64(int64(TotalLeaves)+1), false)

	// ---------------------------------------------------------------
	// 5. Per-opening: modular reduction, leaf hash, Merkle proof.
	// ---------------------------------------------------------------
	var leafHashes [OpeningsCount]frontend.Variable

	for k := 0; k < OpeningsCount; k++ {
		// 5a. Reconstruct rawIndex from 20-bit window of randomness.
		bitOffset := k * MaxTreeDepth
		randWindow := make([]frontend.Variable, MaxTreeDepth)
		for j := 0; j < MaxTreeDepth; j++ {
			randWindow[j] = randBitsFull[bitOffset+j]
		}
		rawIndex := bits.FromBinary(api, randWindow, bits.WithUnconstrainedInputs())

		// 5b. Modular reduction: quotient * numLeaves + leafIndex == rawIndex.
		// Range check: quotient fits in 20 bits (< TotalLeaves).
		api.ToBinary(circuit.Quotients[k], MaxTreeDepth)
		product := api.Mul(circuit.Quotients[k], circuit.NumLeaves)
		sum := api.Add(product, circuit.LeafIndices[k])
		api.AssertIsEqual(sum, rawIndex)

		// Range check: leafIndex < numLeaves.
		comparator.AssertIsLess(circuit.LeafIndices[k], circuit.NumLeaves)

		// 5c. Compute domain-tagged leaf hash: H(1, bytes[k][0..528]).
		leafHasher := hash.NewMerkleDamgardHasher(api, p, 0)
		leafHasher.Write(frontend.Variable(crypto.DomainTagReal))
		leafHasher.Write(circuit.Bytes[k][:]...)
		leafHashes[k] = leafHasher.Sum()
		leafHasher.Reset()

		// 5d. Link leaf hash and root hash to sub-circuit.
		api.AssertIsEqual(circuit.MerkleProofs[k].LeafValue, leafHashes[k])
		api.AssertIsEqual(circuit.MerkleProofs[k].RootHash, circuit.RootHash)

		// 5e. Direction enforcement from LeafIndex bits.
		leafBits := api.ToBinary(circuit.LeafIndices[k], MaxTreeDepth)
		for j := 0; j < MaxTreeDepth; j++ {
			api.AssertIsEqual(circuit.MerkleProofs[k].Directions[j], leafBits[j])
		}

		// 5f. Verify Merkle proof (all 20 levels, no skip).
		if err := circuit.MerkleProofs[k].Define(api); err != nil {
			return err
		}
	}

	// ---------------------------------------------------------------
	// 6. Aggregate message: aggMsg = H(leafHash[0], ..., leafHash[7], randomness).
	// ---------------------------------------------------------------
	aggHasher := hash.NewMerkleDamgardHasher(api, p, 0)
	for k := 0; k < OpeningsCount; k++ {
		aggHasher.Write(leafHashes[k])
	}
	aggHasher.Write(circuit.Randomness)
	aggMsg := aggHasher.Sum()
	aggHasher.Reset()

	// ---------------------------------------------------------------
	// 7. VRF commitment: commitment = H(secretKey, aggMsg, randomness, publicKey).
	// ---------------------------------------------------------------
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

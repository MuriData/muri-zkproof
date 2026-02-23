package poi

import (
	"math/big"

	"github.com/MuriData/muri-zkproof/pkg/crypto"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/permutation/poseidon2"
)

// zeroLeafHash is the domain-separated hash for padding leaves, computed once
// at package init. It is used as a circuit constant.
var zeroLeafHash *big.Int

func init() {
	zeroLeafHash = crypto.ComputeZeroLeafHash(ElementSize, NumChunks)
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

	// Boundary proofs (path-only, no byte arrays)
	BoundaryLower BoundaryMerkleProof `gnark:"boundaryLower"`
	BoundaryUpper BoundaryMerkleProof `gnark:"boundaryUpper"`
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
	// 3. NumLeaves validation and boundary proofs.
	// ---------------------------------------------------------------
	// numLeaves ∈ [1, TotalLeaves].
	// Range check: ToBinary(numLeaves - 1, MaxTreeDepth) constrains
	// numLeaves - 1 ∈ [0, 2^20 - 1], i.e. numLeaves ∈ [1, 2^20].
	api.AssertIsEqual(api.IsZero(circuit.NumLeaves), 0)
	api.ToBinary(api.Sub(circuit.NumLeaves, 1), MaxTreeDepth)

	// isFull == 1 when numLeaves == TotalLeaves (tree completely filled).
	totalLeavesConst := frontend.Variable(TotalLeaves)
	isFull := api.IsZero(api.Sub(circuit.NumLeaves, totalLeavesConst))
	isNotFull := api.Sub(1, isFull)

	// Zero leaf hash as circuit constant.
	zeroLeafConst := frontend.Variable(zeroLeafHash)

	// --- Lower boundary: leaf at index (numLeaves - 1) must NOT be zero ---
	lowerIdx := api.Sub(circuit.NumLeaves, 1)
	lowerBits := api.ToBinary(lowerIdx, MaxTreeDepth)
	for j := 0; j < MaxTreeDepth; j++ {
		api.AssertIsEqual(circuit.BoundaryLower.Directions[j], lowerBits[j])
	}
	lowerRoot, err := circuit.BoundaryLower.ComputeRoot(api)
	if err != nil {
		return err
	}
	api.AssertIsEqual(lowerRoot, circuit.RootHash)
	// LeafHash != zeroLeafHash (non-zero diff)
	api.AssertIsEqual(api.IsZero(api.Sub(circuit.BoundaryLower.LeafHash, zeroLeafConst)), 0)

	// --- Upper boundary: leaf at index numLeaves must equal zero ---
	// When isFull, index numLeaves = TotalLeaves doesn't exist in the tree.
	// Use safeUpperIdx = 0 when isFull (produces valid 20-bit decomposition)
	// and guard all assertions so they're trivially satisfied.
	safeUpperIdx := api.Select(isFull, 0, circuit.NumLeaves)
	upperBits := api.ToBinary(safeUpperIdx, MaxTreeDepth)
	for j := 0; j < MaxTreeDepth; j++ {
		diff := api.Sub(circuit.BoundaryUpper.Directions[j], upperBits[j])
		api.AssertIsEqual(api.Mul(isNotFull, diff), 0)
	}
	upperRoot, err := circuit.BoundaryUpper.ComputeRoot(api)
	if err != nil {
		return err
	}
	// Root must match (guarded when isFull)
	rootDiff := api.Sub(upperRoot, circuit.RootHash)
	api.AssertIsEqual(api.Mul(isNotFull, rootDiff), 0)
	// LeafHash must equal zeroLeafHash (guarded when isFull)
	leafDiff := api.Sub(circuit.BoundaryUpper.LeafHash, zeroLeafConst)
	api.AssertIsEqual(api.Mul(isNotFull, leafDiff), 0)

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

		// 5c. Compute domain-tagged leaf hash: H(1, bytes[k][0..527]).
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

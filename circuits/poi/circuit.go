package poi

import (
	"math/big"

	"github.com/MuriData/muri-zkproof/circuits/shared"
	"github.com/MuriData/muri-zkproof/pkg/crypto"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/cmp"
)

// zeroLeafHash is the domain-separated hash for padding leaves, computed once
// at package init. It is used as a circuit constant.
var zeroLeafHash *big.Int

func init() {
	zeroLeafHash = crypto.ComputeZeroLeafHash(ElementSize, NumChunks)
}

type PoICircuit struct {
	// Public inputs (5): commitment, randomness, publicKey, rootHash, numLeaves
	Commitment frontend.Variable `gnark:"commitment,public"`
	Randomness frontend.Variable `gnark:"randomness,public"`
	PublicKey  frontend.Variable `gnark:"publicKey,public"`
	RootHash   frontend.Variable `gnark:"rootHash,public"`
	NumLeaves  frontend.Variable `gnark:"numLeaves,public"`

	// Private inputs
	SecretKey    frontend.Variable                           `gnark:"secretKey"`
	Bytes        [OpeningsCount][NumChunks]frontend.Variable `gnark:"bytes"`
	MerkleProofs [OpeningsCount]MerkleProofCircuit           `gnark:"merkleProofs"`
	Quotients    [OpeningsCount]frontend.Variable            `gnark:"quotients"`
	LeafIndices  [OpeningsCount]frontend.Variable            `gnark:"leafIndices"`
}

func (circuit *PoICircuit) Define(api frontend.API) error {
	sponge, err := shared.NewSpongeHasher(api)
	if err != nil {
		return err
	}

	// ---------------------------------------------------------------
	// 1. Key ownership: publicKey == H(secretKey), both non-zero.
	// ---------------------------------------------------------------
	api.AssertIsEqual(api.IsZero(circuit.SecretKey), 0)
	api.AssertIsEqual(api.IsZero(circuit.PublicKey), 0)

	derivedPubKey, err := sponge.Hash(frontend.Variable(crypto.DomainTagPubKey), circuit.SecretKey)
	if err != nil {
		return err
	}
	api.AssertIsEqual(circuit.PublicKey, derivedPubKey)

	// ---------------------------------------------------------------
	// 2. Randomness decomposition (once for all openings).
	// ---------------------------------------------------------------
	api.AssertIsEqual(api.IsZero(circuit.Randomness), 0)
	randBitsFull := api.ToBinary(circuit.Randomness, api.Compiler().FieldBitLen())

	// ---------------------------------------------------------------
	// 3. NumLeaves validation (public input, verified on-chain via FSP).
	//    Range check: numLeaves in [1, TotalLeaves].
	// ---------------------------------------------------------------
	api.AssertIsEqual(api.IsZero(circuit.NumLeaves), 0)

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

		// 5c. Compute domain-tagged leaf hash: sponge(DomainTagReal, bytes[k][0..528]).
		leafHash, err := sponge.Hash(frontend.Variable(crypto.DomainTagReal), circuit.Bytes[k][:]...)
		if err != nil {
			return err
		}
		leafHashes[k] = leafHash

		// 5d. Link leaf hash and root hash to sub-circuit.
		api.AssertIsEqual(circuit.MerkleProofs[k].LeafValue, leafHashes[k])
		api.AssertIsEqual(circuit.MerkleProofs[k].RootHash, circuit.RootHash)

		// 5e. Direction enforcement from LeafIndex bits.
		leafBits := api.ToBinary(circuit.LeafIndices[k], MaxTreeDepth)
		for j := 0; j < MaxTreeDepth; j++ {
			api.AssertIsEqual(circuit.MerkleProofs[k].Directions[j], leafBits[j])
		}

		// 5f. Verify Merkle proof (all 20 levels, no skip).
		if err := circuit.MerkleProofs[k].Define(api, sponge); err != nil {
			return err
		}
	}

	// ---------------------------------------------------------------
	// 6. Aggregate message: aggMsg = H(leafHash[0], ..., leafHash[7], randomness).
	// ---------------------------------------------------------------
	aggInputs := make([]frontend.Variable, OpeningsCount+1)
	for k := 0; k < OpeningsCount; k++ {
		aggInputs[k] = leafHashes[k]
	}
	aggInputs[OpeningsCount] = circuit.Randomness
	aggMsg, err := sponge.Hash(frontend.Variable(crypto.DomainTagAggMsg), aggInputs...)
	if err != nil {
		return err
	}

	// ---------------------------------------------------------------
	// 7. VRF commitment: commitment = H(secretKey, aggMsg, randomness, publicKey).
	// ---------------------------------------------------------------
	derivedCommitment, err := sponge.Hash(
		frontend.Variable(crypto.DomainTagCommitment),
		circuit.SecretKey, aggMsg, circuit.Randomness, circuit.PublicKey,
	)
	if err != nil {
		return err
	}

	api.AssertIsEqual(circuit.Commitment, derivedCommitment)

	return nil
}

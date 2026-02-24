package fsp

import (
	"math/big"

	"github.com/MuriData/muri-zkproof/pkg/crypto"
	"github.com/MuriData/muri-zkproof/pkg/merkle"
	"github.com/consensys/gnark/frontend"
)

// zeroLeafHash is the domain-separated hash for padding leaves, computed once
// at package init. It is used as a circuit constant.
var zeroLeafHash *big.Int

// zeroSubtreeHashes[j] is the hash of an all-zero subtree of depth j.
// zeroSubtreeHashes[0] = zeroLeafHash, zeroSubtreeHashes[j] = H(zh[j-1], zh[j-1]).
var zeroSubtreeHashes [MaxTreeDepth]*big.Int

func init() {
	zeroLeafHash = crypto.ComputeZeroLeafHash(ElementSize, NumChunks)
	zh := merkle.PrecomputeZeroHashes(MaxTreeDepth, zeroLeafHash)
	for i := 0; i < MaxTreeDepth; i++ {
		zeroSubtreeHashes[i] = zh[i]
	}
}

// FSPCircuit proves the exact file boundary in a Sparse Merkle Tree using a
// single Merkle proof of the last real leaf (numChunks - 1). It checks:
//   - leaf[last] != zeroLeaf  (last chunk contains real data)
//   - At each level where last is a left child, the sibling equals the
//     precomputed zero subtree hash (no real data to the right)
//   - The proof path reconstructs the claimed root
//
// When numChunks == TotalLeaves (full tree), last = 2^20 - 1 has all bits set,
// so it is a right child at every level and no zero-sibling checks are enforced.
type FSPCircuit struct {
	// Public inputs (2)
	RootHash  frontend.Variable `gnark:"rootHash,public"`
	NumChunks frontend.Variable `gnark:"numChunks,public"`

	// Private inputs: single Merkle proof of leaf at numChunks-1
	Proof BoundaryMerkleProof `gnark:"proof"`
}

func (circuit *FSPCircuit) Define(api frontend.API) error {
	// ---------------------------------------------------------------
	// 1. Range check: numChunks in [1, TotalLeaves].
	//    ToBinary(numChunks - 1, MaxTreeDepth) constrains
	//    numChunks - 1 in [0, 2^20 - 1], i.e. numChunks in [1, 2^20].
	// ---------------------------------------------------------------
	api.AssertIsEqual(api.IsZero(circuit.NumChunks), 0)

	lastIdx := api.Sub(circuit.NumChunks, 1)
	lastBits := api.ToBinary(lastIdx, MaxTreeDepth)

	// ---------------------------------------------------------------
	// 2. Direction bits must match the binary decomposition of lastIdx.
	// ---------------------------------------------------------------
	for j := 0; j < MaxTreeDepth; j++ {
		api.AssertIsEqual(circuit.Proof.Directions[j], lastBits[j])
	}

	// ---------------------------------------------------------------
	// 3. Leaf must be non-zero (real data, not padding).
	// ---------------------------------------------------------------
	zeroLeafConst := frontend.Variable(zeroLeafHash)
	api.AssertIsEqual(api.IsZero(api.Sub(circuit.Proof.LeafHash, zeroLeafConst)), 0)

	// ---------------------------------------------------------------
	// 4. Zero-sibling check: at each level where last is a left child
	//    (bit = 0), the sibling must equal the zero subtree hash for
	//    that level. This proves no real chunk exists beyond lastIdx.
	// ---------------------------------------------------------------
	for j := 0; j < MaxTreeDepth; j++ {
		zhConst := frontend.Variable(zeroSubtreeHashes[j])
		isLeftChild := api.Sub(1, lastBits[j]) // 1 if left child, 0 if right
		diff := api.Sub(circuit.Proof.ProofPath[j], zhConst)
		api.AssertIsEqual(api.Mul(isLeftChild, diff), 0)
	}

	// ---------------------------------------------------------------
	// 5. Verify the proof path reconstructs the claimed root.
	// ---------------------------------------------------------------
	root, err := circuit.Proof.ComputeRoot(api)
	if err != nil {
		return err
	}
	api.AssertIsEqual(root, circuit.RootHash)

	return nil
}

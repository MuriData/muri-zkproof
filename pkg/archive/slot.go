package archive

import (
	"math/big"

	"github.com/MuriData/muri-zkproof/pkg/crypto"
	"github.com/MuriData/muri-zkproof/pkg/merkle"
)

// FileMeta describes one file slot in an archive.
type FileMeta struct {
	FileRoot         *big.Int // Merkle root of the file's original chunk tree (depth-20)
	NumChunks        int      // Number of real chunks in this file
	CumulativeChunks int      // Sum of chunks of all prior slots
}

// ComputeSlotLeaf computes the slot leaf hash for a file slot:
// H(DomainTagSlot, fileRoot, numChunks, cumulativeChunks)
func ComputeSlotLeaf(meta FileMeta) *big.Int {
	return crypto.HashSlotLeaf(meta.FileRoot, meta.NumChunks, meta.CumulativeChunks)
}

// ComputeZeroSlotLeaf computes the canonical zero slot leaf for empty slots.
func ComputeZeroSlotLeaf() *big.Int {
	return crypto.HashSlotLeaf(big.NewInt(0), 0, 0)
}

// BuildSlotTree builds a depth-10 sparse Merkle tree over the slot leaves.
// metas should be ordered by slot index (0..len-1); unused slots use the zero slot leaf.
func BuildSlotTree(metas []FileMeta) *merkle.SparseMerkleTree {
	zeroSlotLeaf := ComputeZeroSlotLeaf()

	// Compute slot leaves.
	leafHashes := make([]*big.Int, len(metas))
	for i, m := range metas {
		leafHashes[i] = ComputeSlotLeaf(m)
	}

	// Build SMT at depth 10 using pre-hashed leaves.
	return buildSMTFromHashes(leafHashes, ArchiveIndexDepth, zeroSlotLeaf)
}

// ComputeArchiveOriginalRoot computes H(DomainTagArchiveRoot, slotTreeRoot, totalRealChunks).
func ComputeArchiveOriginalRoot(slotTreeRoot *big.Int, totalRealChunks int) *big.Int {
	return crypto.DeriveArchiveOriginalRoot(slotTreeRoot, totalRealChunks)
}

// buildSMTFromHashes builds a sparse Merkle tree from pre-hashed leaves.
func buildSMTFromHashes(leafHashes []*big.Int, depth int, zeroLeafHash *big.Int) *merkle.SparseMerkleTree {
	zeroHashes := merkle.PrecomputeZeroHashes(depth, zeroLeafHash)

	levels := make([]map[int]*big.Int, depth+1)
	for i := range levels {
		levels[i] = make(map[int]*big.Int)
	}

	for i, h := range leafHashes {
		levels[0][i] = h
	}

	for lvl := 0; lvl < depth; lvl++ {
		parentIndices := make(map[int]bool)
		for idx := range levels[lvl] {
			parentIndices[idx/2] = true
		}
		for parentIdx := range parentIndices {
			leftIdx := parentIdx * 2
			rightIdx := parentIdx*2 + 1

			left, ok := levels[lvl][leftIdx]
			if !ok {
				left = zeroHashes[lvl]
			}
			right, ok := levels[lvl][rightIdx]
			if !ok {
				right = zeroHashes[lvl]
			}
			levels[lvl+1][parentIdx] = merkle.HashNodes(left, right)
		}
	}

	root, ok := levels[depth][0]
	if !ok {
		root = zeroHashes[depth]
	}

	return &merkle.SparseMerkleTree{
		Root:       root,
		Depth:      depth,
		NumLeaves:  len(leafHashes),
		Levels:     levels,
		ZeroHashes: zeroHashes,
	}
}

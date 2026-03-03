package archive

import (
	"fmt"
	"math/big"

	"github.com/MuriData/muri-zkproof/pkg/crypto"
	"github.com/MuriData/muri-zkproof/pkg/merkle"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// ArchiveTree holds the two-layer tree structure for an archive.
// For original trees: SlotTree has DomainTagSlot-hashed slot leaves; proofs go
// depth-20 against fileRoot then depth-10 against slotTreeRoot.
// For replica trees: SlotTree has file subtree roots as leaves; depth-30 proofs
// verify directly against the replica root.
type ArchiveTree struct {
	SlotTree  *merkle.SparseMerkleTree   // depth-10
	FileTrees []*merkle.SparseMerkleTree // one depth-20 SMT per file slot
	Metas     []FileMeta
	IsReplica bool // true for replica trees (slot leaves are file subtree roots)
}

// HashChunk hashes a single chunk using domain-tagged Poseidon2.
func HashChunk(chunk []byte) *big.Int {
	return crypto.HashWithDomainTag(crypto.DomainTagReal, chunk, big.NewInt(1), ElementSize, NumFieldElements)
}

var zeroLeafHash *big.Int

func init() {
	zeroLeafHash = crypto.ComputeZeroLeafHash(ElementSize, NumFieldElements)
}

// ZeroLeafHash returns the canonical padding leaf hash.
func ZeroLeafHash() *big.Int {
	return new(big.Int).Set(zeroLeafHash)
}

// BuildOriginalArchiveTree builds the archive tree from raw file data.
// The slot tree uses DomainTagSlot-hashed slot leaves.
func BuildOriginalArchiveTree(fileDataSlices [][]byte) (*ArchiveTree, error) {
	if len(fileDataSlices) > MaxFileSlots {
		return nil, fmt.Errorf("too many files: %d > %d", len(fileDataSlices), MaxFileSlots)
	}

	metas := make([]FileMeta, len(fileDataSlices))
	fileTrees := make([]*merkle.SparseMerkleTree, len(fileDataSlices))
	cumulativeChunks := 0

	for i, data := range fileDataSlices {
		chunks := merkle.SplitIntoChunks(data, FileSize)
		smt := merkle.GenerateSparseMerkleTree(chunks, FileTreeDepth, HashChunk, zeroLeafHash)
		fileTrees[i] = smt

		metas[i] = FileMeta{
			FileRoot:         smt.Root,
			NumChunks:        len(chunks),
			CumulativeChunks: cumulativeChunks,
		}
		cumulativeChunks += len(chunks)
	}

	slotTree := BuildSlotTree(metas)

	return &ArchiveTree{
		SlotTree:  slotTree,
		FileTrees: fileTrees,
		Metas:     metas,
		IsReplica: false,
	}, nil
}

// BuildReplicaArchiveTree builds the replica tree from sealed enc2 elements.
// The slot tree uses file subtree roots as leaves (plain Merkle, not DomainTagSlot).
// archiveReplicaRoot = depth-10 root over file subtree roots.
func BuildReplicaArchiveTree(enc2Elements []fr.Element, metas []FileMeta) (*ArchiveTree, error) {
	if len(metas) > MaxFileSlots {
		return nil, fmt.Errorf("too many files: %d > %d", len(metas), MaxFileSlots)
	}

	totalChunks := TotalRealChunks(metas)
	expectedElements := totalChunks * ElementsPerChunk
	if len(enc2Elements) != expectedElements {
		return nil, fmt.Errorf("element count %d != expected %d (totalChunks=%d × %d)",
			len(enc2Elements), expectedElements, totalChunks, ElementsPerChunk)
	}

	fileTrees := make([]*merkle.SparseMerkleTree, len(metas))
	for i, m := range metas {
		chunks := make([][]byte, m.NumChunks)
		for c := 0; c < m.NumChunks; c++ {
			elemStart := (m.CumulativeChunks + c) * ElementsPerChunk
			chunks[c] = elementsToChunkBytes(enc2Elements[elemStart : elemStart+ElementsPerChunk])
		}
		smt := merkle.GenerateSparseMerkleTree(chunks, FileTreeDepth, HashChunk, zeroLeafHash)
		fileTrees[i] = smt
	}

	// Replica slot tree: leaves are file subtree roots (not DomainTagSlot-wrapped).
	// The zero leaf for the upper layer is the root of an all-zero depth-20 subtree.
	zeroFileRoot := merkle.PrecomputeZeroHashes(FileTreeDepth, zeroLeafHash)[FileTreeDepth]
	fileRoots := make([]*big.Int, len(fileTrees))
	for i, ft := range fileTrees {
		fileRoots[i] = ft.Root
	}
	replicaSlotTree := buildSMTFromHashes(fileRoots, ArchiveIndexDepth, zeroFileRoot)

	return &ArchiveTree{
		SlotTree:  replicaSlotTree,
		FileTrees: fileTrees,
		Metas:     metas,
		IsReplica: true,
	}, nil
}

// GetDepth30Proof composes a depth-20 file proof and depth-10 slot proof
// into a depth-30 proof. Only valid for replica trees.
func (at *ArchiveTree) GetDepth30Proof(physicalPos int) ([]*big.Int, []int) {
	slotIndex := physicalPos >> FileTreeDepth
	localChunkIndex := physicalPos & ((1 << FileTreeDepth) - 1)

	fileSiblings, fileDirections := at.FileTrees[slotIndex].GetProof(localChunkIndex)
	slotSiblings, slotDirections := at.SlotTree.GetProof(slotIndex)

	siblings := make([]*big.Int, ArchiveTreeDepth)
	directions := make([]int, ArchiveTreeDepth)
	copy(siblings[:FileTreeDepth], fileSiblings)
	copy(directions[:FileTreeDepth], fileDirections)
	copy(siblings[FileTreeDepth:], slotSiblings)
	copy(directions[FileTreeDepth:], slotDirections)

	return siblings, directions
}

// GetDepth10SlotProof returns a depth-10 Merkle proof for the given slot index.
func (at *ArchiveTree) GetDepth10SlotProof(slotIndex int) ([]*big.Int, []int) {
	return at.SlotTree.GetProof(slotIndex)
}

// GetDepth20FileProof returns a depth-20 Merkle proof for a chunk within a file subtree.
func (at *ArchiveTree) GetDepth20FileProof(slotIndex, localChunkIndex int) ([]*big.Int, []int) {
	return at.FileTrees[slotIndex].GetProof(localChunkIndex)
}

// GetLeafHash returns the leaf hash at the given physical position.
func (at *ArchiveTree) GetLeafHash(physicalPos int) *big.Int {
	slotIndex := physicalPos >> FileTreeDepth
	localChunkIndex := physicalPos & ((1 << FileTreeDepth) - 1)
	if slotIndex >= len(at.FileTrees) {
		return zeroLeafHash
	}
	return at.FileTrees[slotIndex].GetLeafHash(localChunkIndex)
}

// Root returns the tree root. For replicas, this is archiveReplicaRoot.
// For originals, this is the slot tree root (which gets wrapped with
// DomainTagArchiveRoot to form archiveOriginalRoot externally).
func (at *ArchiveTree) Root() *big.Int {
	return at.SlotTree.Root
}

// elementsToChunkBytes converts field elements to chunk bytes for hashing.
func elementsToChunkBytes(elements []fr.Element) []byte {
	buf := make([]byte, len(elements)*ElementSize)
	for i, e := range elements {
		b := e.Bytes()
		copy(buf[i*ElementSize:(i+1)*ElementSize], b[32-ElementSize:])
	}
	return buf
}

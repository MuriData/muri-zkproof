package merkle

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"runtime"
	"strconv"
	"sync"

	"github.com/MuriData/muri-zkproof/pkg/crypto"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// MerkleNode represents a node in the Merkle tree.
type MerkleNode struct {
	Hash   *big.Int
	Left   *MerkleNode
	Right  *MerkleNode
	Parent *MerkleNode
	IsLeaf bool
}

// MerkleTree represents the complete Merkle tree.
type MerkleTree struct {
	Root       *MerkleNode
	Leaves     []*MerkleNode
	FileSize   int64
	ChunkCount int
}

// HashFunc is the function used to hash leaf chunks. Callers provide it so the
// merkle package stays independent of circuit-specific hashing parameters.
type HashFunc func(chunk []byte) *big.Int

// NewMerkleNode creates a new Merkle tree node.
func NewMerkleNode(hash *big.Int, left, right *MerkleNode) *MerkleNode {
	node := &MerkleNode{
		Hash:   hash,
		Left:   left,
		Right:  right,
		IsLeaf: left == nil && right == nil,
	}

	if left != nil {
		left.Parent = node
	}
	if right != nil {
		right.Parent = node
	}

	return node
}

// SplitIntoChunks splits the file data into chunkSize-sized chunks.
// The last chunk is zero-padded so that every returned slice has the same
// length. An empty input produces a single zero chunk.
func SplitIntoChunks(data []byte, chunkSize int) [][]byte {
	var chunks [][]byte

	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			// Last chunk - pad with zeros
			chunk := make([]byte, chunkSize)
			copy(chunk, data[i:])
			chunks = append(chunks, chunk)
		} else {
			chunks = append(chunks, data[i:end])
		}
	}

	if len(chunks) == 0 {
		chunks = append(chunks, make([]byte, chunkSize))
	}

	return chunks
}

// HashNodes hashes two node hashes together to create parent hash.
// Uses Poseidon2 sponge with DomainTagNode for domain separation.
func HashNodes(left, right *big.Int) *big.Int {
	var lFr, rFr fr.Element
	lFr.SetBigInt(left)
	rFr.SetBigInt(right)

	result := crypto.SpongeHashFr(crypto.DomainTagNode, lFr, rFr)
	out := new(big.Int)
	result.BigInt(out)
	return out
}

func maxLeavesForDepth(depth int) (int, error) {
	if depth < 0 {
		return 0, fmt.Errorf("tree depth must be non-negative")
	}
	if depth >= strconv.IntSize-1 {
		return 0, fmt.Errorf("tree depth %d is too large", depth)
	}
	return 1 << depth, nil
}

func validateLeafCapacity(depth, numLeaves int) error {
	maxLeaves, err := maxLeavesForDepth(depth)
	if err != nil {
		return err
	}
	if numLeaves > maxLeaves {
		return fmt.Errorf("tree depth %d supports at most %d leaves, got %d", depth, maxLeaves, numLeaves)
	}
	return nil
}

// GenerateMerkleTree builds a Merkle tree from pre-split chunks.
// hashLeaf is used to hash each leaf chunk (typically Poseidon2 with randomness=1).
// chunkSize is the expected size of each chunk (used for zero-padding fallback).
func GenerateMerkleTree(chunks [][]byte, chunkSize int, hashLeaf HashFunc) *MerkleTree {
	if len(chunks) == 0 {
		// No chunks provided - create a single zero chunk
		chunks = [][]byte{make([]byte, chunkSize)}
	}

	// Pad to at least two leaves and then to the next power-of-two by
	// repeating existing chunks.
	chunks = padToPowerOfTwo(chunks)

	// Create leaf nodes by hashing each chunk
	leaves := make([]*MerkleNode, len(chunks))
	for i, chunk := range chunks {
		leaves[i] = NewMerkleNode(hashLeaf(chunk), nil, nil)
	}

	// Build the tree bottom-up
	currentLevel := leaves
	for len(currentLevel) > 1 {
		nextLevel := make([]*MerkleNode, 0, (len(currentLevel)+1)/2)
		for i := 0; i < len(currentLevel); i += 2 {
			left := currentLevel[i]
			var right *MerkleNode
			if i+1 < len(currentLevel) {
				right = currentLevel[i+1]
			} else {
				// Duplicate the last node for odd counts
				right = left
			}

			parent := NewMerkleNode(HashNodes(left.Hash, right.Hash), left, right)
			nextLevel = append(nextLevel, parent)
		}
		currentLevel = nextLevel
	}

	return &MerkleTree{
		Root:       currentLevel[0],
		Leaves:     leaves,
		FileSize:   int64(len(chunks) * chunkSize),
		ChunkCount: len(chunks),
	}
}

// GetRoot returns the root hash of the Merkle tree.
func (mt *MerkleTree) GetRoot() *big.Int {
	if mt.Root == nil {
		return big.NewInt(0)
	}
	return mt.Root.Hash
}

// GetLeafCount returns the number of leaf nodes.
func (mt *MerkleTree) GetLeafCount() int {
	return len(mt.Leaves)
}

// GetHeight returns the height of the tree (number of levels).
func (mt *MerkleTree) GetHeight() int {
	if mt.Root == nil {
		return 0
	}
	return getNodeHeight(mt.Root)
}

// getNodeHeight calculates the height of a node recursively.
func getNodeHeight(node *MerkleNode) int {
	if node == nil || node.IsLeaf {
		return 1
	}

	leftHeight := getNodeHeight(node.Left)
	rightHeight := getNodeHeight(node.Right)

	if leftHeight > rightHeight {
		return leftHeight + 1
	}
	return rightHeight + 1
}

// GetMerkleProof generates a Merkle proof for the leaf at the given index.
func (mt *MerkleTree) GetMerkleProof(leafIndex int) ([]*big.Int, []bool, error) {
	if leafIndex < 0 || leafIndex >= len(mt.Leaves) {
		return nil, nil, fmt.Errorf("invalid leaf index: %d", leafIndex)
	}

	var proof []*big.Int
	var directions []bool // true for right, false for left

	current := mt.Leaves[leafIndex]

	for current.Parent != nil {
		parent := current.Parent

		if parent.Left == current {
			// Current is left child, so sibling is right
			if parent.Right != nil {
				proof = append(proof, parent.Right.Hash)
				directions = append(directions, true) // sibling is on the right
			}
		} else {
			// Current is right child, so sibling is left
			if parent.Left != nil {
				proof = append(proof, parent.Left.Hash)
				directions = append(directions, false) // sibling is on the left
			}
		}

		current = parent
	}

	return proof, directions, nil
}

// VerifyMerkleProof verifies a Merkle proof for a given leaf hash.
func VerifyMerkleProof(leafHash *big.Int, proof []*big.Int, directions []bool, rootHash *big.Int) bool {
	if len(proof) != len(directions) {
		return false
	}

	current := leafHash

	for i := 0; i < len(proof); i++ {
		sibling := proof[i]
		isRight := directions[i]

		if isRight {
			// Sibling is on the right
			current = HashNodes(current, sibling)
		} else {
			// Sibling is on the left
			current = HashNodes(sibling, current)
		}
	}

	return current.Cmp(rootHash) == 0
}

// String returns a string representation of the tree structure.
func (mt *MerkleTree) String() string {
	if mt.Root == nil {
		return "Empty tree"
	}

	var buf bytes.Buffer
	printNode(mt.Root, "", true, &buf)
	return buf.String()
}

// printNode recursively prints the tree structure.
func printNode(node *MerkleNode, prefix string, isLast bool, buf *bytes.Buffer) {
	if node == nil {
		return
	}

	// Print current node
	connector := "├── "
	if isLast {
		connector = "└── "
	}

	nodeType := "Node"
	if node.IsLeaf {
		nodeType = "Leaf"
	}

	buf.WriteString(fmt.Sprintf("%s%s%s: %s\n", prefix, connector, nodeType, node.Hash.String()[:16]+"..."))

	// Calculate prefix for children
	childPrefix := prefix
	if isLast {
		childPrefix += "    "
	} else {
		childPrefix += "│   "
	}

	// Print children
	if node.Left != nil || node.Right != nil {
		if node.Left != nil {
			printNode(node.Left, childPrefix, node.Right == nil, buf)
		}
		if node.Right != nil {
			printNode(node.Right, childPrefix, true, buf)
		}
	}
}

// padToPowerOfTwo duplicates existing chunks until the slice length is at least
// two and then the next power of two. The minimum-two rule guarantees proof
// depth >= 1, so singleton files remain provable without allowing 0-depth paths.
func padToPowerOfTwo(chunks [][]byte) [][]byte {
	n := len(chunks)
	if n == 0 {
		return chunks
	}

	// Compute next power of two >= n.
	nextPow := 1
	for nextPow < n {
		nextPow <<= 1
	}
	if nextPow < 2 {
		nextPow = 2
	}

	// Duplicate chunks in round-robin fashion until we reach nextPow length.
	for i := 0; len(chunks) < nextPow; i++ {
		chunks = append(chunks, chunks[i%n])
	}
	return chunks
}

// ---------------------------------------------------------------------------
// Sparse Merkle Tree (fixed-depth, fr.Element + flat slices)
// ---------------------------------------------------------------------------

// HashFuncFr hashes a single chunk and returns the leaf hash as fr.Element.
// This is the function signature used by the sparse Merkle tree builder.
type HashFuncFr func(chunk []byte) fr.Element

// HashNodesFr hashes two child hashes to produce a parent hash, operating
// entirely in the fr.Element domain without *big.Int conversion.
func HashNodesFr(left, right fr.Element) fr.Element {
	return crypto.SpongeHashFr(crypto.DomainTagNode, left, right)
}

// SparseMerkleTree represents a fixed-depth Merkle tree where levels are
// stored as contiguous flat slices. Real leaves occupy indices 0..NumLeaves-1;
// all other positions use precomputed zero-subtree hashes.
type SparseMerkleTree struct {
	Root       fr.Element
	Depth      int
	NumLeaves  int
	Levels     [][]fr.Element // levels[0] = leaves, levels[depth] = root
	ZeroHashes []fr.Element
}

// PrecomputeZeroHashes builds the zero-subtree hash chain:
//
//	zeroHashes[0] = zeroLeafHash
//	zeroHashes[i] = HashNodesFr(zeroHashes[i-1], zeroHashes[i-1])
//
// The returned slice has length depth+1 (indices 0..depth).
func PrecomputeZeroHashes(depth int, zeroLeafHash fr.Element) []fr.Element {
	zh := make([]fr.Element, depth+1)
	zh[0] = zeroLeafHash
	for i := 1; i <= depth; i++ {
		zh[i] = HashNodesFr(zh[i-1], zh[i-1])
	}
	return zh
}

// levelSize returns the number of entries at a given tree level for a tree
// with numLeaves real leaves.
func levelSize(numLeaves, level int) int {
	if numLeaves == 0 {
		return 0
	}
	s := numLeaves
	for i := 0; i < level; i++ {
		s = (s + 1) / 2
	}
	return s
}

// parallelBuildThreshold: levels with more parents than this use parallel workers.
const parallelBuildThreshold = 512

// GenerateSparseMerkleTree builds a fixed-depth sparse Merkle tree from
// pre-split chunks. Real leaves occupy indices 0..len(chunks)-1; all other
// positions use the precomputed zero-subtree hashes.
//
// Leaf hashing and the bottom-up tree build are both parallelized.
func GenerateSparseMerkleTree(chunks [][]byte, depth int, hashLeaf HashFuncFr, zeroLeafHash fr.Element) (*SparseMerkleTree, error) {
	numLeaves := len(chunks)
	if err := validateLeafCapacity(depth, numLeaves); err != nil {
		return nil, err
	}

	zeroHashes := PrecomputeZeroHashes(depth, zeroLeafHash)

	// Allocate levels.
	levels := make([][]fr.Element, depth+1)
	for lvl := 0; lvl <= depth; lvl++ {
		levels[lvl] = make([]fr.Element, levelSize(numLeaves, lvl))
	}

	// Parallel leaf hashing.
	if numLeaves > 0 {
		numWorkers := runtime.NumCPU()
		if numWorkers > numLeaves {
			numWorkers = numLeaves
		}
		if numWorkers < 1 {
			numWorkers = 1
		}

		var wg sync.WaitGroup
		work := make(chan int, numLeaves)
		for w := 0; w < numWorkers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for i := range work {
					levels[0][i] = hashLeaf(chunks[i])
				}
			}()
		}
		for i := range chunks {
			work <- i
		}
		close(work)
		wg.Wait()
	}

	// Build tree bottom-up.
	buildTreeLevels(levels, zeroHashes, depth)

	var root fr.Element
	if len(levels[depth]) > 0 {
		root = levels[depth][0]
	} else {
		root = zeroHashes[depth]
	}

	return &SparseMerkleTree{
		Root:       root,
		Depth:      depth,
		NumLeaves:  numLeaves,
		Levels:     levels,
		ZeroHashes: zeroHashes,
	}, nil
}

// buildTreeLevels builds intermediate tree levels bottom-up, using parallel
// workers for levels with more parents than parallelBuildThreshold.
func buildTreeLevels(levels [][]fr.Element, zeroHashes []fr.Element, depth int) {
	numCPU := runtime.NumCPU()

	for lvl := 0; lvl < depth; lvl++ {
		cur := levels[lvl]
		numParents := len(levels[lvl+1])
		if numParents == 0 {
			continue
		}
		next := levels[lvl+1]
		zh := zeroHashes[lvl]

		if numParents > parallelBuildThreshold && numCPU > 1 {
			numWorkers := numCPU
			if numWorkers > numParents {
				numWorkers = numParents
			}

			var wg sync.WaitGroup
			work := make(chan int, numParents)
			for w := 0; w < numWorkers; w++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for p := range work {
						left := cur[2*p]
						var right fr.Element
						if 2*p+1 < len(cur) {
							right = cur[2*p+1]
						} else {
							right = zh
						}
						next[p] = HashNodesFr(left, right)
					}
				}()
			}
			for p := 0; p < numParents; p++ {
				work <- p
			}
			close(work)
			wg.Wait()
		} else {
			for p := 0; p < numParents; p++ {
				left := cur[2*p]
				var right fr.Element
				if 2*p+1 < len(cur) {
					right = cur[2*p+1]
				} else {
					right = zh
				}
				next[p] = HashNodesFr(left, right)
			}
		}
	}
}

// BuildSMTFromLeafHashes constructs a sparse Merkle tree from pre-computed leaf
// hashes. This allows leaf hashing to be parallelized externally (e.g. across
// multiple WASM workers) while the tree assembly happens in a single goroutine.
func BuildSMTFromLeafHashes(leafHashes []fr.Element, depth int, zeroLeafHash fr.Element) (*SparseMerkleTree, error) {
	numLeaves := len(leafHashes)
	if err := validateLeafCapacity(depth, numLeaves); err != nil {
		return nil, err
	}
	zeroHashes := PrecomputeZeroHashes(depth, zeroLeafHash)

	levels := make([][]fr.Element, depth+1)
	for lvl := 0; lvl <= depth; lvl++ {
		levels[lvl] = make([]fr.Element, levelSize(numLeaves, lvl))
	}

	copy(levels[0], leafHashes)

	buildTreeLevels(levels, zeroHashes, depth)

	var root fr.Element
	if len(levels[depth]) > 0 {
		root = levels[depth][0]
	} else {
		root = zeroHashes[depth]
	}

	return &SparseMerkleTree{
		Root:       root,
		Depth:      depth,
		NumLeaves:  numLeaves,
		Levels:     levels,
		ZeroHashes: zeroHashes,
	}, nil
}

// GetProof returns a fixed-size Merkle proof for the leaf at the given index.
func (smt *SparseMerkleTree) GetProof(leafIndex int) ([]fr.Element, []int) {
	siblings := make([]fr.Element, smt.Depth)
	directions := make([]int, smt.Depth)

	idx := leafIndex
	for lvl := 0; lvl < smt.Depth; lvl++ {
		var sibIdx int
		if idx%2 == 0 {
			sibIdx = idx + 1
			directions[lvl] = 0
		} else {
			sibIdx = idx - 1
			directions[lvl] = 1
		}

		if sibIdx >= 0 && sibIdx < len(smt.Levels[lvl]) {
			siblings[lvl] = smt.Levels[lvl][sibIdx]
		} else {
			siblings[lvl] = smt.ZeroHashes[lvl]
		}

		idx /= 2
	}

	return siblings, directions
}

// GetLeafHash returns the hash at the given leaf index, using the zero leaf
// hash for positions beyond the real leaves.
func (smt *SparseMerkleTree) GetLeafHash(leafIndex int) fr.Element {
	if leafIndex >= 0 && leafIndex < len(smt.Levels[0]) {
		return smt.Levels[0][leafIndex]
	}
	return smt.ZeroHashes[0]
}

// RootBigInt returns the root hash as *big.Int for callers that need it
// (e.g. hex formatting, Solidity fixture generation).
func (smt *SparseMerkleTree) RootBigInt() *big.Int {
	out := new(big.Int)
	smt.Root.BigInt(out)
	return out
}

// ---------------------------------------------------------------------------
// SMT Serialization (binary format for persistence)
// ---------------------------------------------------------------------------
//
// Format (compatible with the original map-based format):
//   uint32(depth) | uint32(numLeaves)
//   For each level 0..depth:
//     uint32(count)
//     For each entry:
//       uint32(index) | [32]byte(hash as big-endian fr.Element)
//
// Zero hashes are NOT stored — they are recomputed from zeroLeafHash on load.

// Save writes the sparse Merkle tree to w in a deterministic binary format.
func (smt *SparseMerkleTree) Save(w io.Writer) error {
	if err := binary.Write(w, binary.BigEndian, uint32(smt.Depth)); err != nil {
		return fmt.Errorf("write depth: %w", err)
	}
	if err := binary.Write(w, binary.BigEndian, uint32(smt.NumLeaves)); err != nil {
		return fmt.Errorf("write numLeaves: %w", err)
	}

	for lvl := 0; lvl <= smt.Depth; lvl++ {
		entries := smt.Levels[lvl]
		if err := binary.Write(w, binary.BigEndian, uint32(len(entries))); err != nil {
			return fmt.Errorf("write level %d count: %w", lvl, err)
		}

		for idx := range entries {
			if err := binary.Write(w, binary.BigEndian, uint32(idx)); err != nil {
				return fmt.Errorf("write level %d index %d: %w", lvl, idx, err)
			}
			b := entries[idx].Bytes()
			if _, err := w.Write(b[:]); err != nil {
				return fmt.Errorf("write level %d hash %d: %w", lvl, idx, err)
			}
		}
	}

	return nil
}

// LoadSparseMerkleTree reads a sparse Merkle tree from r that was written by
// Save. The zeroLeafHash is needed to recompute the zero-subtree hash chain.
func LoadSparseMerkleTree(r io.Reader, zeroLeafHash fr.Element) (*SparseMerkleTree, error) {
	var depth, numLeaves uint32
	if err := binary.Read(r, binary.BigEndian, &depth); err != nil {
		return nil, fmt.Errorf("read depth: %w", err)
	}
	if err := binary.Read(r, binary.BigEndian, &numLeaves); err != nil {
		return nil, fmt.Errorf("read numLeaves: %w", err)
	}

	zeroHashes := PrecomputeZeroHashes(int(depth), zeroLeafHash)

	levels := make([][]fr.Element, depth+1)
	for lvl := 0; lvl <= int(depth); lvl++ {
		var count uint32
		if err := binary.Read(r, binary.BigEndian, &count); err != nil {
			return nil, fmt.Errorf("read level %d count: %w", lvl, err)
		}

		entries := make([]fr.Element, count)
		var hashBuf [32]byte
		for j := 0; j < int(count); j++ {
			var idx uint32
			if err := binary.Read(r, binary.BigEndian, &idx); err != nil {
				return nil, fmt.Errorf("read level %d index: %w", lvl, err)
			}
			if _, err := io.ReadFull(r, hashBuf[:]); err != nil {
				return nil, fmt.Errorf("read level %d hash: %w", lvl, err)
			}
			if int(idx) < len(entries) {
				entries[idx].SetBytes(hashBuf[:])
			}
		}
		levels[lvl] = entries
	}

	var root fr.Element
	if len(levels[depth]) > 0 {
		root = levels[depth][0]
	} else {
		root = zeroHashes[depth]
	}

	return &SparseMerkleTree{
		Root:       root,
		Depth:      int(depth),
		NumLeaves:  int(numLeaves),
		Levels:     levels,
		ZeroHashes: zeroHashes,
	}, nil
}

// sortInts sorts a slice of ints in ascending order (insertion sort,
// suitable for the typically small per-level entry counts).
func sortInts(s []int) {
	for i := 1; i < len(s); i++ {
		key := s[i]
		j := i - 1
		for j >= 0 && s[j] > key {
			s[j+1] = s[j]
			j--
		}
		s[j+1] = key
	}
}

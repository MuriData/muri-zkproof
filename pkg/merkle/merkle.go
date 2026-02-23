package merkle

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
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
// Inputs are converted to canonical 32-byte fr.Element encoding so that
// a zero value writes 32 zero bytes (matching the circuit) instead of
// the empty slice returned by big.Int.Bytes().
func HashNodes(left, right *big.Int) *big.Int {
	h := poseidon2.NewMerkleDamgardHasher()

	var lFr, rFr fr.Element
	lFr.SetBigInt(left)
	rFr.SetBigInt(right)

	lBytes := lFr.Bytes()
	rBytes := rFr.Bytes()
	h.Write(lBytes[:])
	h.Write(rBytes[:])

	return new(big.Int).SetBytes(h.Sum(nil))
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
// Sparse Merkle Tree (fixed-depth, for PoI circuit with domain separation)
// ---------------------------------------------------------------------------

// SparseMerkleTree represents a fixed-depth Merkle tree where only real leaves
// are stored. Missing (padding) positions use precomputed zero-subtree hashes.
type SparseMerkleTree struct {
	Root       *big.Int
	Depth      int
	NumLeaves  int               // actual number of real leaves
	Levels     []map[int]*big.Int // levels[0] = leaves, levels[depth] has the root
	ZeroHashes []*big.Int         // zeroHashes[i] = hash of an all-zero subtree at level i
}

// PrecomputeZeroHashes builds the zero-subtree hash chain:
//
//	zeroHashes[0] = zeroLeafHash
//	zeroHashes[i] = HashNodes(zeroHashes[i-1], zeroHashes[i-1])
//
// The returned slice has length depth+1 (indices 0..depth).
func PrecomputeZeroHashes(depth int, zeroLeafHash *big.Int) []*big.Int {
	zh := make([]*big.Int, depth+1)
	zh[0] = new(big.Int).Set(zeroLeafHash)
	for i := 1; i <= depth; i++ {
		zh[i] = HashNodes(zh[i-1], zh[i-1])
	}
	return zh
}

// GenerateSparseMerkleTree builds a fixed-depth sparse Merkle tree from
// pre-split chunks. Real leaves occupy indices 0..len(chunks)-1; all other
// positions use the precomputed zero-subtree hashes.
//
// hashLeaf hashes a single chunk to produce the leaf value.
// zeroLeafHash is the domain-separated hash for padding leaves.
func GenerateSparseMerkleTree(chunks [][]byte, depth int, hashLeaf HashFunc, zeroLeafHash *big.Int) *SparseMerkleTree {
	numLeaves := len(chunks)
	if numLeaves == 0 {
		numLeaves = 0 // empty tree is valid (root = zeroHashes[depth])
	}

	zeroHashes := PrecomputeZeroHashes(depth, zeroLeafHash)

	// Allocate levels: levels[0] = leaf level, ..., levels[depth] = root level.
	levels := make([]map[int]*big.Int, depth+1)
	for i := range levels {
		levels[i] = make(map[int]*big.Int)
	}

	// Populate leaf level with real chunk hashes.
	for i, chunk := range chunks {
		levels[0][i] = hashLeaf(chunk)
	}

	// Build bottom-up.
	for lvl := 0; lvl < depth; lvl++ {
		// Collect all parent indices that have at least one real child.
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

			levels[lvl+1][parentIdx] = HashNodes(left, right)
		}
	}

	// Root is the single entry at levels[depth], or the zero hash if empty.
	root, ok := levels[depth][0]
	if !ok {
		root = zeroHashes[depth]
	}

	return &SparseMerkleTree{
		Root:       root,
		Depth:      depth,
		NumLeaves:  len(chunks),
		Levels:     levels,
		ZeroHashes: zeroHashes,
	}
}

// GetProof returns a fixed-size Merkle proof for the leaf at the given index.
// The proof has exactly smt.Depth elements. siblings[i] is the sibling hash at
// level i, and directions[i] is the circuit-format direction:
//
//	0 = current node is the left child  (sibling on the right)
//	1 = current node is the right child (sibling on the left)
func (smt *SparseMerkleTree) GetProof(leafIndex int) ([]*big.Int, []int) {
	siblings := make([]*big.Int, smt.Depth)
	directions := make([]int, smt.Depth)

	idx := leafIndex
	for lvl := 0; lvl < smt.Depth; lvl++ {
		var siblingIdx int
		if idx%2 == 0 {
			// Current is left child; sibling is right.
			siblingIdx = idx + 1
			directions[lvl] = 0
		} else {
			// Current is right child; sibling is left.
			siblingIdx = idx - 1
			directions[lvl] = 1
		}

		sib, ok := smt.Levels[lvl][siblingIdx]
		if !ok {
			sib = smt.ZeroHashes[lvl]
		}
		siblings[lvl] = sib

		idx /= 2 // move to parent
	}

	return siblings, directions
}

// GetLeafHash returns the hash at the given leaf index, using the zero leaf
// hash for positions beyond the real leaves.
func (smt *SparseMerkleTree) GetLeafHash(leafIndex int) *big.Int {
	h, ok := smt.Levels[0][leafIndex]
	if !ok {
		return smt.ZeroHashes[0]
	}
	return h
}

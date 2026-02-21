package utils

import (
	"bytes"
	"fmt"
	"math/big"

	"github.com/MuriData/muri-zkproof/config"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

// MerkleNode represents a node in the Merkle tree
type MerkleNode struct {
	Hash   *big.Int
	Left   *MerkleNode
	Right  *MerkleNode
	Parent *MerkleNode
	IsLeaf bool
}

// MerkleTree represents the complete Merkle tree
type MerkleTree struct {
	Root       *MerkleNode
	Leaves     []*MerkleNode
	FileSize   int64
	ChunkCount int
}

// NewMerkleNode creates a new Merkle tree node
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

// SplitIntoChunks splits the file data into config.FileSize-sized chunks (16 KB).
// The last chunk is zero-padded so that every returned slice has the same
// length. An empty input produces a single zero chunk. The function is exported
// so that callers outside this file (e.g. tests) can reuse the exact same
// logic and avoid code duplication.
func SplitIntoChunks(data []byte) [][]byte {
	var chunks [][]byte

	for i := 0; i < len(data); i += config.FileSize {
		end := i + config.FileSize
		if end > len(data) {
			// Last chunk - pad with zeros
			chunk := make([]byte, config.FileSize)
			copy(chunk, data[i:])
			chunks = append(chunks, chunk)
		} else {
			chunks = append(chunks, data[i:end])
		}
	}

	if len(chunks) == 0 {
		chunks = append(chunks, make([]byte, config.FileSize))
	}

	return chunks
}

// hashChunk hashes a single chunk using Poseidon2 with randomness = 1
func hashChunk(chunk []byte) *big.Int {
	randomness := big.NewInt(1)
	return Hash(chunk, randomness)
}

// hashNodes hashes two node hashes together to create parent hash.
// Inputs are converted to canonical 32-byte fr.Element encoding so that
// a zero value writes 32 zero bytes (matching the circuit) instead of
// the empty slice returned by big.Int.Bytes().
func hashNodes(left, right *big.Int) *big.Int {
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

func GenerateMerkleTree(chunks [][]byte) *MerkleTree {
	if len(chunks) == 0 {
		// No chunks provided - create a single zero chunk
		chunks = [][]byte{make([]byte, config.FileSize)}
	}

	// Pad to the next power-of-two by repeating existing chunks.
	chunks = padToPowerOfTwo(chunks)

	// Create leaf nodes by hashing each chunk
	leaves := make([]*MerkleNode, len(chunks))
	for i, chunk := range chunks {
		leaves[i] = NewMerkleNode(hashChunk(chunk), nil, nil)
	}

	// Degenerate case: only one chunk
	if len(leaves) == 1 {
		return &MerkleTree{
			Root:       leaves[0],
			Leaves:     leaves,
			FileSize:   int64(len(chunks[0])), // Approximate from first chunk
			ChunkCount: len(chunks),
		}
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

			parent := NewMerkleNode(hashNodes(left.Hash, right.Hash), left, right)
			nextLevel = append(nextLevel, parent)
		}
		currentLevel = nextLevel
	}

	return &MerkleTree{
		Root:       currentLevel[0],
		Leaves:     leaves,
		FileSize:   int64(len(chunks) * config.FileSize), // Approximate
		ChunkCount: len(chunks),
	}
}

// GetRoot returns the root hash of the Merkle tree
func (mt *MerkleTree) GetRoot() *big.Int {
	if mt.Root == nil {
		return big.NewInt(0)
	}
	return mt.Root.Hash
}

// GetLeafCount returns the number of leaf nodes
func (mt *MerkleTree) GetLeafCount() int {
	return len(mt.Leaves)
}

// GetHeight returns the height of the tree (number of levels)
func (mt *MerkleTree) GetHeight() int {
	if mt.Root == nil {
		return 0
	}
	return getNodeHeight(mt.Root)
}

// getNodeHeight calculates the height of a node recursively
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

// GetMerkleProof generates a Merkle proof for the leaf at the given index
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

// VerifyMerkleProof verifies a Merkle proof for a given leaf hash
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
			current = hashNodes(current, sibling)
		} else {
			// Sibling is on the left
			current = hashNodes(sibling, current)
		}
	}

	return current.Cmp(rootHash) == 0
}

// String returns a string representation of the tree structure
func (mt *MerkleTree) String() string {
	if mt.Root == nil {
		return "Empty tree"
	}

	var buf bytes.Buffer
	printNode(mt.Root, "", true, &buf)
	return buf.String()
}

// printNode recursively prints the tree structure
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

// padToPowerOfTwo duplicates existing chunks until the slice length is the next
// power of two. This guarantees every leaf position corresponds to real data.
func padToPowerOfTwo(chunks [][]byte) [][]byte {
	n := len(chunks)
	if n == 0 {
		return chunks
	}

	// Compute next power of two >= n
	nextPow := 1
	for nextPow < n {
		nextPow <<= 1
	}

	// Duplicate chunks in round-robin fashion until we reach nextPow length.
	for i := 0; len(chunks) < nextPow; i++ {
		chunks = append(chunks, chunks[i%n])
	}
	return chunks
}

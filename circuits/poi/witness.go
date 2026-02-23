package poi

import (
	"fmt"
	"math/big"

	"github.com/MuriData/muri-zkproof/pkg/crypto"
	"github.com/MuriData/muri-zkproof/pkg/field"
	"github.com/MuriData/muri-zkproof/pkg/merkle"
	"github.com/consensys/gnark/frontend"
)

// WitnessResult holds the fully populated circuit assignment and derived
// public values that callers typically need for logging or fixture export.
type WitnessResult struct {
	Assignment PoICircuit
	ChunkIndex int
	PublicKey  *big.Int
	Commitment *big.Int
	Msg        *big.Int
}

// PrepareWitness derives all public and private witness values from the
// minimal independent inputs and returns a ready-to-use circuit assignment.
//
// Inputs:
//   - secretKey:  BN254 scalar field element (the prover's private key)
//   - randomness: BN254 scalar field element (public challenge randomness)
//   - chunks:     raw file data split into FileSize-sized chunks
//   - merkleTree: Merkle tree built from the same chunks
func PrepareWitness(secretKey, randomness *big.Int, chunks [][]byte, merkleTree *merkle.MerkleTree) (*WitnessResult, error) {
	if len(merkleTree.Leaves) == 0 {
		return nil, fmt.Errorf("merkle tree has no leaves")
	}
	if len(chunks) == 0 {
		return nil, fmt.Errorf("no chunks provided")
	}

	// --- Deterministic leaf selection from randomness bits ---
	// leafBit = 1 - randBit  (see circuit step 4)
	treeHeight := merkleTree.GetHeight() - 1
	if treeHeight > MaxTreeDepth {
		return nil, fmt.Errorf("tree height %d exceeds MaxTreeDepth %d", treeHeight, MaxTreeDepth)
	}

	var chunkIndex int64
	for i := 0; i < treeHeight; i++ {
		bit := randomness.Bit(i)
		leafBit := 1 - int(bit)
		chunkIndex |= int64(leafBit) << i
	}

	// Index into the original (unpadded) chunks. The Merkle tree may have
	// more leaves than chunks due to power-of-two padding, so use the
	// original chunk count to wrap around safely.
	testData := chunks[int(chunkIndex)%len(chunks)]

	// --- Merkle proof ---
	merkleProof, directions, err := merkleTree.GetMerkleProof(int(chunkIndex))
	if err != nil {
		return nil, fmt.Errorf("get merkle proof: %w", err)
	}
	if len(merkleProof) > MaxTreeDepth {
		return nil, fmt.Errorf("merkle proof length %d exceeds MaxTreeDepth %d", len(merkleProof), MaxTreeDepth)
	}

	var proofPath [MaxTreeDepth]frontend.Variable
	var proofDirections [MaxTreeDepth]frontend.Variable
	for i := 0; i < len(merkleProof) && i < MaxTreeDepth; i++ {
		proofPath[i] = merkleProof[i]
		if directions[i] {
			proofDirections[i] = 0 // sibling on right -> 0
		} else {
			proofDirections[i] = 1 // sibling on left -> 1
		}
	}
	for i := len(merkleProof); i < MaxTreeDepth; i++ {
		proofPath[i] = 0
		proofDirections[i] = 0
	}

	// --- Derived public values ---
	publicKey := crypto.DerivePublicKey(secretKey)
	msg := crypto.Hash(testData, randomness, ElementSize, NumChunks)
	commitment := crypto.DeriveCommitment(secretKey, msg, randomness, publicKey)

	// --- Convert bytes to field elements (fixed-size array) ---
	fieldSlice := field.Bytes2Field(testData, NumChunks, ElementSize)
	var bytesArray [NumChunks]frontend.Variable
	copy(bytesArray[:], fieldSlice)

	// --- Circuit assignment ---
	assignment := PoICircuit{
		SecretKey:  secretKey,
		Bytes:      bytesArray,
		Commitment: commitment,
		Randomness: randomness,
		PublicKey:  publicKey,
		RootHash:   merkleTree.GetRoot(),
		MerkleProof: MerkleProofCircuit{
			RootHash:   merkleTree.GetRoot(),
			LeafValue:  merkleTree.Leaves[chunkIndex].Hash,
			ProofPath:  proofPath,
			Directions: proofDirections,
		},
	}

	return &WitnessResult{
		Assignment: assignment,
		ChunkIndex: int(chunkIndex),
		PublicKey:  publicKey,
		Commitment: commitment,
		Msg:        msg,
	}, nil
}

// HashChunk hashes a single chunk using Poseidon2 with randomness = 1.
// This is the leaf hash function used by the Merkle tree.
func HashChunk(chunk []byte) *big.Int {
	randomness := big.NewInt(1)
	return crypto.Hash(chunk, randomness, ElementSize, NumChunks)
}

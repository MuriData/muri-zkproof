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
	Assignment   PoICircuit
	ChunkIndices [OpeningsCount]int
	PublicKey    *big.Int
	Commitment   *big.Int
	AggMsg       *big.Int
}

// PrepareWitness derives all public and private witness values from the
// minimal independent inputs and returns a ready-to-use circuit assignment.
//
// For each of the OpeningsCount openings, a leaf index is derived from a
// distinct bit window of the randomness value (bits [k*MaxTreeDepth ..
// k*MaxTreeDepth + treeHeight - 1]).
func PrepareWitness(secretKey, randomness *big.Int, chunks [][]byte, merkleTree *merkle.MerkleTree) (*WitnessResult, error) {
	if len(merkleTree.Leaves) == 0 {
		return nil, fmt.Errorf("merkle tree has no leaves")
	}
	if len(chunks) == 0 {
		return nil, fmt.Errorf("no chunks provided")
	}

	treeHeight := merkleTree.GetHeight() - 1
	if treeHeight > MaxTreeDepth {
		return nil, fmt.Errorf("tree height %d exceeds MaxTreeDepth %d", treeHeight, MaxTreeDepth)
	}

	publicKey := crypto.DerivePublicKey(secretKey)

	var assignment PoICircuit
	assignment.SecretKey = secretKey
	assignment.Randomness = randomness
	assignment.PublicKey = publicKey
	assignment.RootHash = merkleTree.GetRoot()

	var chunkIndices [OpeningsCount]int
	var leafHashes [OpeningsCount]*big.Int

	for k := 0; k < OpeningsCount; k++ {
		// Derive leaf index from bit window [k*MaxTreeDepth .. k*MaxTreeDepth + treeHeight - 1].
		bitOffset := k * MaxTreeDepth
		var chunkIndex int64
		for i := 0; i < treeHeight; i++ {
			bit := randomness.Bit(bitOffset + i)
			leafBit := 1 - int(bit)
			chunkIndex |= int64(leafBit) << i
		}

		// Wrap into the original (unpadded) chunk array.
		dataIdx := int(chunkIndex) % len(chunks)
		chunkIndices[k] = int(chunkIndex)
		testData := chunks[dataIdx]

		// Merkle proof for this opening.
		merkleProof, directions, err := merkleTree.GetMerkleProof(int(chunkIndex))
		if err != nil {
			return nil, fmt.Errorf("opening %d: get merkle proof: %w", k, err)
		}
		if len(merkleProof) > MaxTreeDepth {
			return nil, fmt.Errorf("opening %d: merkle proof length %d exceeds MaxTreeDepth %d", k, len(merkleProof), MaxTreeDepth)
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

		// Convert chunk bytes to field elements.
		fieldSlice := field.Bytes2Field(testData, NumChunks, ElementSize)
		var bytesArray [NumChunks]frontend.Variable
		copy(bytesArray[:], fieldSlice)

		assignment.Bytes[k] = bytesArray
		assignment.MerkleProofs[k] = MerkleProofCircuit{
			RootHash:   merkleTree.GetRoot(),
			LeafValue:  merkleTree.Leaves[chunkIndex].Hash,
			ProofPath:  proofPath,
			Directions: proofDirections,
		}

		// Compute native leaf hash for aggregate message.
		leafHashes[k] = HashChunk(testData)
	}

	// Aggregate message and commitment.
	aggMsg := crypto.DeriveAggMsg(leafHashes[:], randomness)
	commitment := crypto.DeriveCommitment(secretKey, aggMsg, randomness, publicKey)

	assignment.Commitment = commitment

	return &WitnessResult{
		Assignment:   assignment,
		ChunkIndices: chunkIndices,
		PublicKey:    publicKey,
		Commitment:   commitment,
		AggMsg:       aggMsg,
	}, nil
}

// HashChunk hashes a single chunk using Poseidon2 with randomness = 1.
// This is the leaf hash function used by the Merkle tree.
func HashChunk(chunk []byte) *big.Int {
	randomness := big.NewInt(1)
	return crypto.Hash(chunk, randomness, ElementSize, NumChunks)
}

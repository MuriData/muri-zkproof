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
	ChunkIndices [OpeningsCount]int // leafIndex (into original chunks) per opening
	NumLeaves    int
	PublicKey    *big.Int
	Commitment   *big.Int
	AggMsg       *big.Int
}

// PrepareWitness derives all public and private witness values from the
// minimal independent inputs and returns a ready-to-use circuit assignment.
//
// For each of the OpeningsCount openings, a raw 20-bit index is extracted from
// the randomness, then reduced modulo numLeaves to select a real chunk.
func PrepareWitness(secretKey, randomness *big.Int, chunks [][]byte, smt *merkle.SparseMerkleTree) (*WitnessResult, error) {
	if smt.NumLeaves == 0 {
		return nil, fmt.Errorf("sparse merkle tree has no leaves")
	}
	if len(chunks) == 0 {
		return nil, fmt.Errorf("no chunks provided")
	}
	if len(chunks) != smt.NumLeaves {
		return nil, fmt.Errorf("chunk count %d does not match tree numLeaves %d", len(chunks), smt.NumLeaves)
	}

	numLeaves := smt.NumLeaves
	publicKey := crypto.DerivePublicKey(secretKey)

	var assignment PoICircuit
	assignment.SecretKey = secretKey
	assignment.Randomness = randomness
	assignment.PublicKey = publicKey
	assignment.RootHash = smt.Root
	assignment.NumLeaves = numLeaves

	var chunkIndices [OpeningsCount]int
	var leafHashes [OpeningsCount]*big.Int

	numLeavesBig := big.NewInt(int64(numLeaves))

	for k := 0; k < OpeningsCount; k++ {
		// Derive rawIndex from 20-bit window [k*MaxTreeDepth .. k*MaxTreeDepth+19].
		// bits.FromBinary uses little-endian, so bit 0 is LSB.
		bitOffset := k * MaxTreeDepth
		var rawIndex int64
		for i := 0; i < MaxTreeDepth; i++ {
			bit := randomness.Bit(bitOffset + i)
			rawIndex |= int64(bit) << i
		}

		// Modular reduction: leafIndex = rawIndex % numLeaves.
		rawIndexBig := big.NewInt(rawIndex)
		quotientBig := new(big.Int).Div(rawIndexBig, numLeavesBig)
		leafIndexBig := new(big.Int).Mod(rawIndexBig, numLeavesBig)
		leafIndex := int(leafIndexBig.Int64())

		chunkIndices[k] = leafIndex
		chunkData := chunks[leafIndex]

		// Merkle proof for this opening from the SMT.
		siblings, directions := smt.GetProof(leafIndex)

		var proofPath [MaxTreeDepth]frontend.Variable
		var proofDirections [MaxTreeDepth]frontend.Variable
		for i := 0; i < MaxTreeDepth; i++ {
			proofPath[i] = siblings[i]
			proofDirections[i] = directions[i]
		}

		// Convert chunk bytes to field elements.
		fieldSlice := field.Bytes2Field(chunkData, NumChunks, ElementSize)
		var bytesArray [NumChunks]frontend.Variable
		copy(bytesArray[:], fieldSlice)

		assignment.Bytes[k] = bytesArray
		assignment.Quotients[k] = quotientBig
		assignment.LeafIndices[k] = leafIndexBig
		assignment.MerkleProofs[k] = MerkleProofCircuit{
			RootHash:   smt.Root,
			LeafValue:  smt.GetLeafHash(leafIndex),
			ProofPath:  proofPath,
			Directions: proofDirections,
		}

		leafHashes[k] = HashChunk(chunkData)
	}

	// Boundary proofs.
	assignment.BoundaryLower = prepareBoundaryProof(smt, numLeaves-1)
	if numLeaves < TotalLeaves {
		assignment.BoundaryUpper = prepareBoundaryProof(smt, numLeaves)
	} else {
		// isFull: provide dummy upper boundary (all checks are guarded).
		assignment.BoundaryUpper = dummyBoundaryProof(smt)
	}

	// Aggregate message and commitment.
	aggMsg := crypto.DeriveAggMsg(leafHashes[:], randomness)
	commitment := crypto.DeriveCommitment(secretKey, aggMsg, randomness, publicKey)
	assignment.Commitment = commitment

	return &WitnessResult{
		Assignment:   assignment,
		ChunkIndices: chunkIndices,
		NumLeaves:    numLeaves,
		PublicKey:    publicKey,
		Commitment:   commitment,
		AggMsg:       aggMsg,
	}, nil
}

// prepareBoundaryProof creates a BoundaryMerkleProof for a given leaf index.
func prepareBoundaryProof(smt *merkle.SparseMerkleTree, leafIndex int) BoundaryMerkleProof {
	siblings, directions := smt.GetProof(leafIndex)
	leafHash := smt.GetLeafHash(leafIndex)

	var proofPath [MaxTreeDepth]frontend.Variable
	var proofDirections [MaxTreeDepth]frontend.Variable
	for i := 0; i < MaxTreeDepth; i++ {
		proofPath[i] = siblings[i]
		proofDirections[i] = directions[i]
	}

	return BoundaryMerkleProof{
		LeafHash:   leafHash,
		ProofPath:  proofPath,
		Directions: proofDirections,
	}
}

// dummyBoundaryProof returns a BoundaryMerkleProof with zero values.
// Used when numLeaves == TotalLeaves and the upper boundary check is skipped.
func dummyBoundaryProof(smt *merkle.SparseMerkleTree) BoundaryMerkleProof {
	var proofPath [MaxTreeDepth]frontend.Variable
	var proofDirections [MaxTreeDepth]frontend.Variable
	for i := 0; i < MaxTreeDepth; i++ {
		proofPath[i] = big.NewInt(0)
		proofDirections[i] = 0
	}

	return BoundaryMerkleProof{
		LeafHash:   big.NewInt(0),
		ProofPath:  proofPath,
		Directions: proofDirections,
	}
}

// HashChunk hashes a single chunk using Poseidon2 with domain tag = 1
// (real leaf) and randomness = 1. This is the leaf hash function used by
// the sparse Merkle tree.
func HashChunk(chunk []byte) *big.Int {
	return crypto.HashWithDomainTag(crypto.DomainTagReal, chunk, big.NewInt(1), ElementSize, NumChunks)
}

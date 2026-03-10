package poi

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/MuriData/muri-zkproof/pkg/crypto"
	"github.com/MuriData/muri-zkproof/pkg/field"
	"github.com/MuriData/muri-zkproof/pkg/merkle"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
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
	if smt.NumLeaves > TotalLeaves {
		return nil, fmt.Errorf("numLeaves %d exceeds circuit capacity %d", smt.NumLeaves, TotalLeaves)
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
	var leafHashes [OpeningsCount]fr.Element

	numLeavesBig := big.NewInt(int64(numLeaves))

	// Per-opening results collected by parallel goroutines.
	type openingResult struct {
		chunkIndex  int
		bytesArray  [NumChunks]frontend.Variable
		quotient    *big.Int
		leafIndex   *big.Int
		merkleProof MerkleProofCircuit
		leafHash    fr.Element
	}
	var results [OpeningsCount]openingResult

	// The 8 openings are independent — compute them in parallel.
	var wg sync.WaitGroup
	for k := 0; k < OpeningsCount; k++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()

			// Derive rawIndex from 20-bit window [k*MaxTreeDepth .. k*MaxTreeDepth+19].
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

			results[k] = openingResult{
				chunkIndex: leafIndex,
				bytesArray: bytesArray,
				quotient:   quotientBig,
				leafIndex:  leafIndexBig,
				merkleProof: MerkleProofCircuit{
					RootHash:   smt.Root,
					LeafValue:  smt.GetLeafHash(leafIndex),
					ProofPath:  proofPath,
					Directions: proofDirections,
				},
				leafHash: smt.GetLeafHash(leafIndex),
			}
		}(k)
	}
	wg.Wait()

	// Collect results into assignment.
	for k := 0; k < OpeningsCount; k++ {
		r := &results[k]
		chunkIndices[k] = r.chunkIndex
		leafHashes[k] = r.leafHash
		assignment.Bytes[k] = r.bytesArray
		assignment.Quotients[k] = r.quotient
		assignment.LeafIndices[k] = r.leafIndex
		assignment.MerkleProofs[k] = r.merkleProof
	}

	// Aggregate message and commitment.
	// Convert fr.Element leaf hashes to *big.Int for DeriveAggMsg.
	leafHashesBig := make([]*big.Int, OpeningsCount)
	for i := 0; i < OpeningsCount; i++ {
		leafHashesBig[i] = new(big.Int)
		leafHashes[i].BigInt(leafHashesBig[i])
	}
	aggMsg := crypto.DeriveAggMsg(leafHashesBig, randomness)
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

// HashChunk hashes a single chunk using Poseidon2 with domain tag = 1
// (real leaf). This is the leaf hash function used by the sparse Merkle tree.
func HashChunk(chunk []byte) fr.Element {
	return crypto.HashLeafFr(crypto.DomainTagReal, chunk, ElementSize, NumChunks)
}

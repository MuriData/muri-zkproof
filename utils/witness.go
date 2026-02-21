package utils

import (
	"fmt"
	"math/big"

	"github.com/MuriData/muri-zkproof/circuits"
	"github.com/MuriData/muri-zkproof/config"
	"github.com/consensys/gnark/frontend"
)

// WitnessResult holds the fully populated circuit assignment and derived
// public values that callers typically need for logging or fixture export.
type WitnessResult struct {
	Assignment circuits.PoICircuit
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
//   - chunks:     raw file data split into config.FileSize-sized chunks
//   - merkleTree: Merkle tree built from the same chunks
func PrepareWitness(secretKey, randomness *big.Int, chunks [][]byte, merkleTree *MerkleTree) (*WitnessResult, error) {
	leafCount := len(merkleTree.Leaves)
	if leafCount == 0 {
		return nil, fmt.Errorf("merkle tree has no leaves")
	}

	// --- Deterministic leaf selection from randomness bits ---
	// leafBit = 1 - randBit  (see circuit step 4)
	treeHeight := merkleTree.GetHeight() - 1
	if treeHeight > config.MaxTreeDepth {
		treeHeight = config.MaxTreeDepth
	}

	var chunkIndex int64
	for i := 0; i < treeHeight; i++ {
		bit := randomness.Bit(i)
		leafBit := 1 - int(bit)
		chunkIndex |= int64(leafBit) << i
	}

	testData := chunks[int(chunkIndex)%leafCount]

	// --- Merkle proof ---
	merkleProof, directions, err := merkleTree.GetMerkleProof(int(chunkIndex))
	if err != nil {
		return nil, fmt.Errorf("get merkle proof: %w", err)
	}
	if len(merkleProof) > config.MaxTreeDepth {
		merkleProof = merkleProof[:config.MaxTreeDepth]
		directions = directions[:config.MaxTreeDepth]
	}

	var proofPath [config.MaxTreeDepth]frontend.Variable
	var proofDirections [config.MaxTreeDepth]frontend.Variable
	for i := 0; i < len(merkleProof) && i < config.MaxTreeDepth; i++ {
		proofPath[i] = merkleProof[i]
		if directions[i] {
			proofDirections[i] = 0 // sibling on right -> 0
		} else {
			proofDirections[i] = 1 // sibling on left -> 1
		}
	}
	for i := len(merkleProof); i < config.MaxTreeDepth; i++ {
		proofPath[i] = 0
		proofDirections[i] = 0
	}

	// --- Derived public values ---
	publicKey := DerivePublicKey(secretKey)
	msg := Hash(testData, randomness)
	commitment := DeriveCommitment(secretKey, msg, randomness, publicKey)

	// --- Circuit assignment ---
	assignment := circuits.PoICircuit{
		SecretKey:  secretKey,
		Bytes:      Bytes2Field(testData),
		Commitment: commitment,
		Randomness: randomness,
		PublicKey:  publicKey,
		RootHash:   merkleTree.GetRoot(),
		MerkleProof: circuits.MerkleProofCircuit{
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

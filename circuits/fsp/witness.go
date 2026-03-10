package fsp

import (
	"fmt"

	"github.com/MuriData/muri-zkproof/pkg/crypto"
	"github.com/MuriData/muri-zkproof/pkg/merkle"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/frontend"
)

// WitnessResult holds the fully populated circuit assignment.
type WitnessResult struct {
	Assignment FSPCircuit
	NumLeaves  int
}

// PrepareWitness derives all public and private witness values from a sparse
// Merkle tree and returns a ready-to-use circuit assignment.
func PrepareWitness(smt *merkle.SparseMerkleTree) (*WitnessResult, error) {
	if smt.NumLeaves == 0 {
		return nil, fmt.Errorf("sparse merkle tree has no leaves")
	}

	numLeaves := smt.NumLeaves

	var assignment FSPCircuit
	assignment.RootHash = smt.Root
	assignment.NumChunks = numLeaves

	// Single Merkle proof of the last real leaf (numLeaves - 1).
	assignment.Proof = prepareBoundaryProof(smt, numLeaves-1)

	return &WitnessResult{
		Assignment: assignment,
		NumLeaves:  numLeaves,
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

// HashChunk hashes a single chunk using Poseidon2 with domain tag = 1
// (real leaf). This is the leaf hash function used by the sparse Merkle tree.
func HashChunk(chunk []byte) fr.Element {
	return crypto.HashLeafFr(crypto.DomainTagReal, chunk, ElementSize, NumChunks)
}

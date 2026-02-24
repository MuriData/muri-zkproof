package fsp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/MuriData/muri-zkproof/pkg/crypto"
	"github.com/MuriData/muri-zkproof/pkg/merkle"
	"github.com/MuriData/muri-zkproof/pkg/setup"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
)

// ProofFixture holds all values needed for Solidity tests.
type ProofFixture struct {
	SolidityProof [8]string `json:"solidity_proof"`
	RootHash      string    `json:"root_hash"`
	NumChunks     string    `json:"num_chunks"`
}

// ExportProofFixture generates a deterministic proof fixture for Solidity tests.
// keysDir is the directory containing the proving and verifying keys.
func ExportProofFixture(keysDir string) ([]byte, error) {
	// 1. Compile the circuit
	fmt.Println("Compiling circuit...")
	ccs, err := setup.CompileCircuit(&FSPCircuit{})
	if err != nil {
		return nil, fmt.Errorf("compile circuit: %w", err)
	}

	// 2. Load proving and verifying keys
	fmt.Println("Loading keys...")
	pk, vk, err := setup.LoadKeys(keysDir, "fsp")
	if err != nil {
		return nil, fmt.Errorf("load keys: %w", err)
	}

	// 3. Create a deterministic test file (128 KB = 8 chunks).
	testFileData := make([]byte, 8*FileSize)
	for i := range testFileData {
		testFileData[i] = byte(i % 256)
	}
	chunks := merkle.SplitIntoChunks(testFileData, FileSize)
	fmt.Printf("Chunks: %d\n", len(chunks))

	// 4. Build sparse Merkle tree and prepare the witness
	zeroLeaf := crypto.ComputeZeroLeafHash(ElementSize, NumChunks)
	smt := merkle.GenerateSparseMerkleTree(chunks, MaxTreeDepth, HashChunk, zeroLeaf)
	fmt.Printf("Merkle root: 0x%x\n", smt.Root.Bytes())
	fmt.Printf("Leaves: %d, Depth: %d\n", smt.NumLeaves, smt.Depth)

	result, err := PrepareWitness(smt)
	if err != nil {
		return nil, fmt.Errorf("prepare witness: %w", err)
	}

	fmt.Printf("NumLeaves: %d\n", result.NumLeaves)

	// 5. Create witness and generate proof
	witness, err := frontend.NewWitness(&result.Assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("create witness: %w", err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		return nil, fmt.Errorf("extract public witness: %w", err)
	}

	fmt.Println("Generating proof...")
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		return nil, fmt.Errorf("prove: %w", err)
	}

	// 6. Verify proof in Go
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}
	fmt.Println("Proof verified successfully in Go!")

	// 7. Extract proof points for Solidity
	bn254Proof := proof.(*groth16bn254.Proof)

	aX := new(big.Int)
	aY := new(big.Int)
	bn254Proof.Ar.X.BigInt(aX)
	bn254Proof.Ar.Y.BigInt(aY)

	bX0 := new(big.Int)
	bX1 := new(big.Int)
	bY0 := new(big.Int)
	bY1 := new(big.Int)
	bn254Proof.Bs.X.A0.BigInt(bX0)
	bn254Proof.Bs.X.A1.BigInt(bX1)
	bn254Proof.Bs.Y.A0.BigInt(bY0)
	bn254Proof.Bs.Y.A1.BigInt(bY1)

	cX := new(big.Int)
	cY := new(big.Int)
	bn254Proof.Krs.X.BigInt(cX)
	bn254Proof.Krs.Y.BigInt(cY)

	// Solidity format: [A.x, A.y, B.x1, B.x0, B.y1, B.y0, C.x, C.y]
	solidityProof := [8]*big.Int{aX, aY, bX1, bX0, bY1, bY0, cX, cY}

	fixture := ProofFixture{
		RootHash:  fmt.Sprintf("0x%064x", smt.Root),
		NumChunks: fmt.Sprintf("%d", result.NumLeaves),
	}
	for i := 0; i < 8; i++ {
		fixture.SolidityProof[i] = fmt.Sprintf("0x%064x", solidityProof[i])
	}

	jsonOut, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal fixture: %w", err)
	}

	// Print diagnostic info
	fmt.Println("\n=== PROOF FIXTURE (JSON) ===")
	fmt.Println(string(jsonOut))

	fmt.Println("\n=== SOLIDITY CONSTANTS ===")
	fmt.Printf("    // Public inputs\n")
	fmt.Printf("    uint256 constant FSP_FILE_ROOT = %s;\n", fixture.RootHash)
	fmt.Printf("    uint32 constant FSP_NUM_CHUNKS = %s;\n", fixture.NumChunks)
	fmt.Println()
	fmt.Printf("    // Proof (uint256[8])\n")
	for i := 0; i < 8; i++ {
		fmt.Printf("    uint256 constant FSP_PROOF_%d = %s;\n", i, fixture.SolidityProof[i])
	}

	// Public witness info
	fmt.Println("\n=== PUBLIC WITNESS ORDER ===")
	fmt.Println("In gnark circuit (= Solidity order): [rootHash, numChunks]")
	var pubWitBuf bytes.Buffer
	_, err = publicWitness.WriteTo(&pubWitBuf)
	if err != nil {
		return nil, fmt.Errorf("write public witness: %w", err)
	}
	fmt.Printf("Public witness size: %d bytes\n", pubWitBuf.Len())

	return jsonOut, nil
}

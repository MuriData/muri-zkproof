package poi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/MuriData/muri-zkproof/pkg/crypto"
	"github.com/MuriData/muri-zkproof/pkg/merkle"
	"github.com/MuriData/muri-zkproof/pkg/setup"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
)

// ProofFixture holds all values needed for Solidity tests.
type ProofFixture struct {
	SolidityProof [8]string `json:"solidity_proof"`
	Randomness    string    `json:"randomness"`
	RootHash      string    `json:"root_hash"`
	Commitment    string    `json:"commitment"`
	PublicKey     string    `json:"public_key"`
}

// ExportProofFixture generates a deterministic proof fixture for Solidity tests.
// keysDir is the directory containing the proving and verifying keys.
func ExportProofFixture(keysDir string) ([]byte, error) {
	// 1. Compile the circuit
	fmt.Println("Compiling circuit...")
	ccs, err := setup.CompileCircuit(&PoICircuit{})
	if err != nil {
		return nil, fmt.Errorf("compile circuit: %w", err)
	}

	// 2. Load proving and verifying keys
	fmt.Println("Loading keys...")
	pk, vk, err := setup.LoadKeys(keysDir, "poi")
	if err != nil {
		return nil, fmt.Errorf("load keys: %w", err)
	}

	// 3. Create a deterministic test file (128 KB = 8 chunks).
	//    Using 8 chunks exercises all OpeningsCount openings with distinct leaves.
	testFileData := make([]byte, 8*FileSize)
	for i := range testFileData {
		testFileData[i] = byte(i % 256)
	}
	chunks := merkle.SplitIntoChunks(testFileData, FileSize)
	fmt.Printf("Chunks: %d\n", len(chunks))

	// 4. Deterministic randomness and secret key
	randomness := new(big.Int).SetUint64(42)
	var randFr fr.Element
	randFr.SetBigInt(randomness)
	randomness = new(big.Int)
	randFr.BigInt(randomness)

	secretKey := new(big.Int).SetUint64(12345)
	var skFr fr.Element
	skFr.SetBigInt(secretKey)
	secretKey = new(big.Int)
	skFr.BigInt(secretKey)

	// 5. Build sparse Merkle tree and prepare the full witness
	zeroLeaf := crypto.ComputeZeroLeafHash(ElementSize, NumChunks)
	smt := merkle.GenerateSparseMerkleTree(chunks, MaxTreeDepth, HashChunk, zeroLeaf)
	fmt.Printf("Merkle root: 0x%x\n", smt.Root.Bytes())
	fmt.Printf("Leaves: %d, Depth: %d\n", smt.NumLeaves, smt.Depth)

	result, err := PrepareWitness(secretKey, randomness, chunks, smt)
	if err != nil {
		return nil, fmt.Errorf("prepare witness: %w", err)
	}

	fmt.Printf("Selected chunk indices: %v\n", result.ChunkIndices)
	fmt.Printf("Public key (H(sk)): 0x%064x\n", result.PublicKey)
	fmt.Printf("Commitment: 0x%064x\n", result.Commitment)

	// 6. Create witness and generate proof
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

	// 7. Verify proof in Go
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}
	fmt.Println("Proof verified successfully in Go!")

	// 8. Extract proof points for Solidity
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
		Randomness: fmt.Sprintf("0x%064x", randomness),
		RootHash:   fmt.Sprintf("0x%064x", smt.Root),
		Commitment: fmt.Sprintf("0x%064x", result.Commitment),
		PublicKey:  fmt.Sprintf("0x%064x", result.PublicKey),
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
	fmt.Printf("    uint256 constant ZK_RANDOMNESS = %s;\n", fixture.Randomness)
	fmt.Printf("    uint256 constant ZK_FILE_ROOT = %s;\n", fixture.RootHash)
	fmt.Printf("    bytes32 constant ZK_COMMITMENT = bytes32(%s);\n", fixture.Commitment)
	fmt.Printf("    uint256 constant ZK_PUB_KEY = %s;\n", fixture.PublicKey)
	fmt.Println()
	fmt.Printf("    // Proof (uint256[8])\n")
	for i := 0; i < 8; i++ {
		fmt.Printf("    uint256 constant ZK_PROOF_%d = %s;\n", i, fixture.SolidityProof[i])
	}

	fmt.Println("\n=== HELPER ===")
	fmt.Println("    function _zkProof() internal pure returns (uint256[8] memory proof) {")
	for i := 0; i < 8; i++ {
		fmt.Printf("        proof[%d] = ZK_PROOF_%d;\n", i, i)
	}
	fmt.Println("    }")

	// Public witness info
	fmt.Println("\n=== PUBLIC WITNESS ORDER ===")
	fmt.Println("In gnark circuit (= Solidity order): [commitment, randomness, publicKey, rootHash]")
	var pubWitBuf bytes.Buffer
	_, err = publicWitness.WriteTo(&pubWitBuf)
	if err != nil {
		return nil, fmt.Errorf("write public witness: %w", err)
	}
	fmt.Printf("Public witness size: %d bytes\n", pubWitBuf.Len())

	fmt.Println("\ngnark public input order (from circuit struct tags):")
	fmt.Println("  [0] commitment")
	fmt.Println("  [1] randomness")
	fmt.Println("  [2] publicKey")
	fmt.Println("  [3] rootHash")
	fmt.Println("\nMake sure Market.sol's publicInputs array matches this order!")

	return jsonOut, nil
}

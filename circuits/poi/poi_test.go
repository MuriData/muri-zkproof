package poi_test

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/MuriData/muri-zkproof/circuits/poi"
	"github.com/MuriData/muri-zkproof/pkg/crypto"
	"github.com/MuriData/muri-zkproof/pkg/merkle"
	"github.com/MuriData/muri-zkproof/pkg/setup"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

// TestPoICircuitEndToEnd compiles the circuit, performs a dev setup,
// generates random data, builds a Merkle tree, prepares a witness,
// generates a proof, and verifies it.
func TestPoICircuitEndToEnd(t *testing.T) {
	// 1. Compile
	ccs, err := setup.CompileCircuit(&poi.PoICircuit{})
	if err != nil {
		t.Fatalf("compile circuit: %v", err)
	}

	// 2. Dev setup (single-party, not for production)
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("groth16 setup: %v", err)
	}

	// 3. Generate random test data (128 KB = 8 chunks of 16 KB)
	testFileSize := 8 * poi.FileSize
	wholeFileData := make([]byte, testFileSize)
	if _, err := rand.Read(wholeFileData); err != nil {
		t.Fatalf("generate random data: %v", err)
	}
	chunks := merkle.SplitIntoChunks(wholeFileData, poi.FileSize)
	t.Logf("Generated %d bytes of random data (%d chunks)", testFileSize, len(chunks))

	// 4. Generate randomness and secret key
	randomness, err := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("generate randomness: %v", err)
	}

	secretKey, err := crypto.GenerateSecretKey()
	if err != nil {
		t.Fatalf("generate secret key: %v", err)
	}

	// 5. Build Merkle tree and prepare witness
	merkleTree := merkle.GenerateMerkleTree(chunks, poi.FileSize, poi.HashChunk)
	t.Logf("Merkle root: 0x%x", merkleTree.GetRoot().Bytes())
	t.Logf("Leaves: %d, Height: %d", merkleTree.GetLeafCount(), merkleTree.GetHeight())

	result, err := poi.PrepareWitness(secretKey, randomness, chunks, merkleTree)
	if err != nil {
		t.Fatalf("prepare witness: %v", err)
	}
	t.Logf("Selected chunk indices: %v", result.ChunkIndices)

	// 6. Create witness and generate proof
	witness, err := frontend.NewWitness(&result.Assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("create witness: %v", err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		t.Fatalf("extract public witness: %v", err)
	}

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	// 7. Verify proof
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	t.Log("ZK proof verified successfully!")
}

// TestPoIMultipleFileSizes verifies the circuit works for various file sizes.
// For small files (< 8 leaves), multiple openings hit the same leaf via wrapping.
func TestPoIMultipleFileSizes(t *testing.T) {
	// Compile and setup once — reuse for all sub-tests.
	ccs, err := setup.CompileCircuit(&poi.PoICircuit{})
	if err != nil {
		t.Fatalf("compile circuit: %v", err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("groth16 setup: %v", err)
	}

	fileSizes := []struct {
		name       string
		chunkCount int
	}{
		{"2_chunks_32KB", 2},
		{"4_chunks_64KB", 4},
		{"8_chunks_128KB", 8},
		{"16_chunks_256KB", 16},
	}

	for _, fs := range fileSizes {
		t.Run(fs.name, func(t *testing.T) {
			testFileSize := fs.chunkCount * poi.FileSize
			wholeFileData := make([]byte, testFileSize)
			if _, err := rand.Read(wholeFileData); err != nil {
				t.Fatalf("generate random data: %v", err)
			}
			chunks := merkle.SplitIntoChunks(wholeFileData, poi.FileSize)
			t.Logf("Chunks: %d", len(chunks))

			randomness, err := rand.Int(rand.Reader, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatalf("generate randomness: %v", err)
			}
			secretKey, err := crypto.GenerateSecretKey()
			if err != nil {
				t.Fatalf("generate secret key: %v", err)
			}

			merkleTree := merkle.GenerateMerkleTree(chunks, poi.FileSize, poi.HashChunk)
			t.Logf("Leaves: %d, Height: %d", merkleTree.GetLeafCount(), merkleTree.GetHeight())

			result, err := poi.PrepareWitness(secretKey, randomness, chunks, merkleTree)
			if err != nil {
				t.Fatalf("prepare witness: %v", err)
			}
			t.Logf("Chunk indices: %v", result.ChunkIndices)

			witness, err := frontend.NewWitness(&result.Assignment, ecc.BN254.ScalarField())
			if err != nil {
				t.Fatalf("create witness: %v", err)
			}
			publicWitness, err := witness.Public()
			if err != nil {
				t.Fatalf("extract public witness: %v", err)
			}

			proof, err := groth16.Prove(ccs, pk, witness)
			if err != nil {
				t.Fatalf("prove: %v", err)
			}

			err = groth16.Verify(proof, vk, publicWitness)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}

			t.Log("Proof verified OK")
		})
	}
}

// TestPoIExportFixture generates a deterministic fixture and verifies
// that it round-trips through JSON.
func TestPoIExportFixture(t *testing.T) {
	// 1. Compile and dev setup
	ccs, err := setup.CompileCircuit(&poi.PoICircuit{})
	if err != nil {
		t.Fatalf("compile circuit: %v", err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("groth16 setup: %v", err)
	}

	// 2. Write keys to temp directory
	tmpDir := t.TempDir()
	if err := setup.ExportKeys(pk, vk, tmpDir, "poi"); err != nil {
		t.Fatalf("export keys: %v", err)
	}

	// 3. Generate fixture
	jsonOut, err := poi.ExportProofFixture(tmpDir)
	if err != nil {
		t.Fatalf("export proof fixture: %v", err)
	}

	// 4. Verify JSON round-trips
	var fixture poi.ProofFixture
	if err := json.Unmarshal(jsonOut, &fixture); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	// Verify fields are non-empty
	if fixture.Randomness == "" {
		t.Fatal("fixture randomness is empty")
	}
	if fixture.RootHash == "" {
		t.Fatal("fixture root hash is empty")
	}
	if fixture.Commitment == "" {
		t.Fatal("fixture commitment is empty")
	}
	if fixture.PublicKey == "" {
		t.Fatal("fixture public key is empty")
	}
	for i, p := range fixture.SolidityProof {
		if p == "" {
			t.Fatalf("fixture solidity proof[%d] is empty", i)
		}
	}

	// Re-marshal and check it matches
	jsonRoundTrip, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("re-marshal fixture: %v", err)
	}
	if string(jsonRoundTrip) != string(jsonOut) {
		t.Fatal("fixture JSON round-trip mismatch")
	}

	fmt.Println("Fixture round-trip OK")
}

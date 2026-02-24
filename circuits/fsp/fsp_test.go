package fsp_test

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/MuriData/muri-zkproof/circuits/fsp"
	"github.com/MuriData/muri-zkproof/pkg/crypto"
	"github.com/MuriData/muri-zkproof/pkg/merkle"
	"github.com/MuriData/muri-zkproof/pkg/setup"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/constraint"
	"github.com/consensys/gnark/frontend"
)

// buildSMT is a test helper that splits data into chunks and builds a
// sparse Merkle tree with domain-separated leaf hashing.
func buildSMT(data []byte) (*merkle.SparseMerkleTree, [][]byte) {
	chunks := merkle.SplitIntoChunks(data, fsp.FileSize)
	zeroLeaf := crypto.ComputeZeroLeafHash(fsp.ElementSize, fsp.NumChunks)
	smt := merkle.GenerateSparseMerkleTree(chunks, fsp.MaxTreeDepth, fsp.HashChunk, zeroLeaf)
	return smt, chunks
}

// proveAndVerify compiles, proves, and verifies an FSP circuit.
func proveAndVerify(t *testing.T, ccs constraint.ConstraintSystem, pk groth16.ProvingKey, vk groth16.VerifyingKey, assignment *fsp.FSPCircuit) {
	t.Helper()

	witness, err := frontend.NewWitness(assignment, ecc.BN254.ScalarField())
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
}

// TestFSPCircuitEndToEnd compiles the circuit, performs a dev setup,
// generates random data, builds a sparse Merkle tree, prepares a witness,
// generates a proof, and verifies it.
func TestFSPCircuitEndToEnd(t *testing.T) {
	// 1. Compile
	ccs, err := setup.CompileCircuit(&fsp.FSPCircuit{})
	if err != nil {
		t.Fatalf("compile circuit: %v", err)
	}

	// 2. Dev setup (single-party, not for production)
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("groth16 setup: %v", err)
	}

	// 3. Generate random test data (128 KB = 8 chunks of 16 KB)
	testFileSize := 8 * fsp.FileSize
	wholeFileData := make([]byte, testFileSize)
	if _, err := rand.Read(wholeFileData); err != nil {
		t.Fatalf("generate random data: %v", err)
	}
	smt, _ := buildSMT(wholeFileData)
	t.Logf("Generated %d bytes of random data (%d chunks)", testFileSize, smt.NumLeaves)
	t.Logf("Merkle root: 0x%x", smt.Root.Bytes())

	// 4. Prepare witness
	result, err := fsp.PrepareWitness(smt)
	if err != nil {
		t.Fatalf("prepare witness: %v", err)
	}
	t.Logf("NumLeaves: %d", result.NumLeaves)

	// 5. Prove and verify
	proveAndVerify(t, ccs, pk, vk, &result.Assignment)
	t.Log("ZK proof verified successfully!")
}

// TestFSPMultipleFileSizes verifies the circuit works for various file sizes.
func TestFSPMultipleFileSizes(t *testing.T) {
	ccs, err := setup.CompileCircuit(&fsp.FSPCircuit{})
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
		{"1_chunk_16KB", 1},
		{"2_chunks_32KB", 2},
		{"4_chunks_64KB", 4},
		{"8_chunks_128KB", 8},
		{"16_chunks_256KB", 16},
	}

	for _, fs := range fileSizes {
		t.Run(fs.name, func(t *testing.T) {
			testFileSize := fs.chunkCount * fsp.FileSize
			wholeFileData := make([]byte, testFileSize)
			if _, err := rand.Read(wholeFileData); err != nil {
				t.Fatalf("generate random data: %v", err)
			}
			smt, _ := buildSMT(wholeFileData)
			t.Logf("Chunks: %d, NumLeaves: %d", fs.chunkCount, smt.NumLeaves)

			result, err := fsp.PrepareWitness(smt)
			if err != nil {
				t.Fatalf("prepare witness: %v", err)
			}
			t.Logf("NumLeaves: %d", result.NumLeaves)

			proveAndVerify(t, ccs, pk, vk, &result.Assignment)
			t.Log("Proof verified OK")
		})
	}
}

// TestFSPExportFixture generates a deterministic fixture and verifies
// that it round-trips through JSON.
func TestFSPExportFixture(t *testing.T) {
	// 1. Compile and dev setup
	ccs, err := setup.CompileCircuit(&fsp.FSPCircuit{})
	if err != nil {
		t.Fatalf("compile circuit: %v", err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("groth16 setup: %v", err)
	}

	// 2. Write keys to temp directory
	tmpDir := t.TempDir()
	if err := setup.ExportKeys(pk, vk, tmpDir, "fsp"); err != nil {
		t.Fatalf("export keys: %v", err)
	}

	// 3. Generate fixture
	jsonOut, err := fsp.ExportProofFixture(tmpDir)
	if err != nil {
		t.Fatalf("export proof fixture: %v", err)
	}

	// 4. Verify JSON round-trips
	var fixture fsp.ProofFixture
	if err := json.Unmarshal(jsonOut, &fixture); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	// Verify fields are non-empty
	if fixture.RootHash == "" {
		t.Fatal("fixture root hash is empty")
	}
	if fixture.NumChunks == "" {
		t.Fatal("fixture num chunks is empty")
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

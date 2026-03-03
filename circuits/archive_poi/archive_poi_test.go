package archive_poi_test

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/MuriData/muri-zkproof/circuits/archive_poi"
	"github.com/MuriData/muri-zkproof/pkg/archive"
	"github.com/MuriData/muri-zkproof/pkg/crypto"
	"github.com/MuriData/muri-zkproof/pkg/merkle"
	"github.com/MuriData/muri-zkproof/pkg/muri"
	"github.com/MuriData/muri-zkproof/pkg/setup"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
)

// buildTestArchive creates a small test archive with the given file sizes (in chunks).
func buildTestArchive(t *testing.T, chunkCounts []int) (
	origTree, replicaTree *archive.ArchiveTree,
	encChunks [][]byte,
	secretKey, randomness *big.Int,
) {
	t.Helper()

	// Create file data
	files := make([][]byte, len(chunkCounts))
	for i, nc := range chunkCounts {
		files[i] = make([]byte, nc*archive.FileSize)
		if _, err := rand.Read(files[i]); err != nil {
			t.Fatalf("generate random data: %v", err)
		}
	}

	var err error
	origTree, err = archive.BuildOriginalArchiveTree(files)
	if err != nil {
		t.Fatalf("build original tree: %v", err)
	}

	totalChunks := archive.TotalRealChunks(origTree.Metas)

	// Convert to elements and seal
	allChunks := make([][]byte, 0, totalChunks)
	for _, f := range files {
		allChunks = append(allChunks, merkle.SplitIntoChunks(f, archive.FileSize)...)
	}

	origElements := chunksToFrElements(allChunks)

	secretKey, err = crypto.GenerateSecretKey()
	if err != nil {
		t.Fatalf("generate secret key: %v", err)
	}
	publicKey := crypto.DerivePublicKey(secretKey)
	archiveOrigRoot := archive.ComputeArchiveOriginalRoot(origTree.SlotTree.Root, totalChunks)
	r := crypto.DeriveGlobalR(publicKey, archiveOrigRoot)

	sealResult := muri.SealArchive(origElements, r)

	replicaTree, err = archive.BuildReplicaArchiveTree(sealResult.Enc2, origTree.Metas)
	if err != nil {
		t.Fatalf("build replica tree: %v", err)
	}

	encChunks = frElementsToChunkBytes(sealResult.Enc2, totalChunks)

	randomness, err = rand.Int(rand.Reader, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("generate randomness: %v", err)
	}

	return
}

// TestArchivePoICompile verifies the circuit compiles and reports constraint count.
func TestArchivePoICompile(t *testing.T) {
	ccs, err := setup.CompileCircuit(&archive_poi.ArchivePoICircuit{})
	if err != nil {
		t.Fatalf("compile circuit: %v", err)
	}
	t.Logf("Archive PoI circuit: %d constraints", ccs.GetNbConstraints())
}

// TestArchivePoIEndToEnd compiles, sets up, proves, and verifies with a small archive.
func TestArchivePoIEndToEnd(t *testing.T) {
	// Compile
	ccs, err := setup.CompileCircuit(&archive_poi.ArchivePoICircuit{})
	if err != nil {
		t.Fatalf("compile circuit: %v", err)
	}
	t.Logf("Constraints: %d", ccs.GetNbConstraints())

	// Dev setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("groth16 setup: %v", err)
	}

	// Build test archive: 3 files with 2, 3, 3 chunks = 8 total chunks
	origTree, replicaTree, encChunks, secretKey, randomness := buildTestArchive(t, []int{2, 3, 3})
	t.Logf("Archive: %d files, %d total chunks", len(origTree.Metas), archive.TotalRealChunks(origTree.Metas))

	// Prepare witness
	result, err := archive_poi.PrepareWitness(secretKey, randomness, origTree, replicaTree, encChunks)
	if err != nil {
		t.Fatalf("prepare witness: %v", err)
	}
	t.Logf("Selected chunk indices: %v", result.ChunkIndices)

	// Prove
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

	// Verify
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	t.Log("Archive PoI proof verified successfully!")
}

// TestArchivePoIExportFixture generates a deterministic fixture and verifies JSON round-trip.
func TestArchivePoIExportFixture(t *testing.T) {
	ccs, err := setup.CompileCircuit(&archive_poi.ArchivePoICircuit{})
	if err != nil {
		t.Fatalf("compile circuit: %v", err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("groth16 setup: %v", err)
	}

	tmpDir := t.TempDir()
	if err := setup.ExportKeys(pk, vk, tmpDir, "archive_poi"); err != nil {
		t.Fatalf("export keys: %v", err)
	}

	jsonOut, err := archive_poi.ExportProofFixture(tmpDir)
	if err != nil {
		t.Fatalf("export proof fixture: %v", err)
	}

	var fixture archive_poi.ProofFixture
	if err := json.Unmarshal(jsonOut, &fixture); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	if fixture.Randomness == "" || fixture.Commitment == "" || fixture.PublicKey == "" {
		t.Fatal("fixture has empty fields")
	}
	if fixture.ArchiveOriginalRoot == "" || fixture.ArchiveReplicaRoot == "" {
		t.Fatal("fixture missing archive roots")
	}
	for i, p := range fixture.SolidityProof {
		if p == "" {
			t.Fatalf("fixture solidity proof[%d] is empty", i)
		}
	}

	jsonRoundTrip, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("re-marshal fixture: %v", err)
	}
	if string(jsonRoundTrip) != string(jsonOut) {
		t.Fatal("fixture JSON round-trip mismatch")
	}
	fmt.Println("Archive PoI fixture round-trip OK")
}

// chunksToFrElements converts raw chunk bytes to a flat fr.Element array.
func chunksToFrElements(chunks [][]byte) []fr.Element {
	totalElements := len(chunks) * archive.ElementsPerChunk
	elements := make([]fr.Element, totalElements)
	for c, chunk := range chunks {
		for e := 0; e < archive.ElementsPerChunk; e++ {
			start := e * archive.ElementSize
			end := start + archive.ElementSize
			if end > len(chunk) {
				end = len(chunk)
			}
			if start < len(chunk) {
				buf := make([]byte, archive.ElementSize)
				copy(buf, chunk[start:end])
				elements[c*archive.ElementsPerChunk+e].SetBytes(buf)
			}
		}
	}
	return elements
}

// frElementsToChunkBytes converts flat fr.Element array to chunk byte arrays.
func frElementsToChunkBytes(elements []fr.Element, totalChunks int) [][]byte {
	chunks := make([][]byte, totalChunks)
	for c := 0; c < totalChunks; c++ {
		buf := make([]byte, archive.ElementsPerChunk*archive.ElementSize)
		for e := 0; e < archive.ElementsPerChunk; e++ {
			b := elements[c*archive.ElementsPerChunk+e].Bytes()
			copy(buf[e*archive.ElementSize:(e+1)*archive.ElementSize], b[32-archive.ElementSize:])
		}
		chunks[c] = buf
	}
	return chunks
}

package archive_muri_test

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/MuriData/muri-zkproof/circuits/archive_muri"
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

// TestArchiveMURICompile verifies the circuit compiles and reports constraint count.
func TestArchiveMURICompile(t *testing.T) {
	ccs, err := setup.CompileCircuit(&archive_muri.ArchiveMURICircuit{})
	if err != nil {
		t.Fatalf("compile circuit: %v", err)
	}
	t.Logf("Archive MURI circuit: %d constraints", ccs.GetNbConstraints())
}

// TestArchiveMURIEndToEnd builds a small archive, seals it, and runs full prove/verify.
func TestArchiveMURIEndToEnd(t *testing.T) {
	// Compile
	ccs, err := setup.CompileCircuit(&archive_muri.ArchiveMURICircuit{})
	if err != nil {
		t.Fatalf("compile circuit: %v", err)
	}
	t.Logf("Constraints: %d", ccs.GetNbConstraints())

	// Dev setup
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("groth16 setup: %v", err)
	}

	// Build test archive: 8 files with 3 chunks each = 24 total chunks
	files := make([][]byte, archive_muri.C)
	for i := range files {
		files[i] = make([]byte, 3*archive.FileSize)
		if _, err := rand.Read(files[i]); err != nil {
			t.Fatalf("generate random data: %v", err)
		}
	}

	origTree, err := archive.BuildOriginalArchiveTree(files)
	if err != nil {
		t.Fatalf("build original tree: %v", err)
	}

	totalChunks := archive.TotalRealChunks(origTree.Metas)
	t.Logf("Archive: %d files, %d total chunks", len(files), totalChunks)

	allChunks := getAllChunks(files)
	origElements := chunksToFrElements(allChunks)

	secretKey, err := crypto.GenerateSecretKey()
	if err != nil {
		t.Fatalf("generate secret key: %v", err)
	}
	publicKey := crypto.DerivePublicKey(secretKey)
	archiveOrigRoot := archive.ComputeArchiveOriginalRoot(origTree.SlotTree.Root, totalChunks)
	globalR := crypto.DeriveGlobalR(publicKey, archiveOrigRoot)

	sealResult := muri.SealArchive(origElements, globalR)

	replicaTree, err := archive.BuildReplicaArchiveTree(sealResult.Enc2, origTree.Metas)
	if err != nil {
		t.Fatalf("build replica tree: %v", err)
	}

	encChunks := frElementsToChunkBytes(sealResult.Enc2, totalChunks)
	origChunks := frElementsToChunkBytes(origElements, totalChunks)

	challengeRandomness, err := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("generate challenge randomness: %v", err)
	}

	result, err := archive_muri.PrepareWitness(
		publicKey, challengeRandomness,
		origTree, replicaTree,
		origElements, sealResult.Enc2, sealResult.Enc1,
		origChunks, encChunks, globalR,
	)
	if err != nil {
		t.Fatalf("prepare witness: %v", err)
	}

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
	t.Log("Archive MURI proof verified successfully!")
}

// TestArchiveMURIExportFixture generates a deterministic fixture and verifies JSON round-trip.
func TestArchiveMURIExportFixture(t *testing.T) {
	ccs, err := setup.CompileCircuit(&archive_muri.ArchiveMURICircuit{})
	if err != nil {
		t.Fatalf("compile circuit: %v", err)
	}
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatalf("groth16 setup: %v", err)
	}

	tmpDir := t.TempDir()
	if err := setup.ExportKeys(pk, vk, tmpDir, "archive_muri"); err != nil {
		t.Fatalf("export keys: %v", err)
	}

	jsonOut, err := archive_muri.ExportProofFixture(tmpDir)
	if err != nil {
		t.Fatalf("export proof fixture: %v", err)
	}

	var fixture archive_muri.ProofFixture
	if err := json.Unmarshal(jsonOut, &fixture); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	if fixture.ArchiveOriginalRoot == "" || fixture.ArchiveReplicaRoot == "" {
		t.Fatal("fixture missing archive roots")
	}
	if fixture.PublicKey == "" || fixture.ChallengeRandomness == "" {
		t.Fatal("fixture missing public key or challenge randomness")
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
	fmt.Println("Archive MURI fixture round-trip OK")
}

func getAllChunks(files [][]byte) [][]byte {
	var all [][]byte
	for _, f := range files {
		all = append(all, merkle.SplitIntoChunks(f, archive.FileSize)...)
	}
	return all
}

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

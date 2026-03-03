package archive_muri

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/MuriData/muri-zkproof/pkg/archive"
	"github.com/MuriData/muri-zkproof/pkg/crypto"
	"github.com/MuriData/muri-zkproof/pkg/merkle"
	"github.com/MuriData/muri-zkproof/pkg/muri"
	"github.com/MuriData/muri-zkproof/pkg/setup"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
)

// ProofFixture holds values needed for Solidity tests.
type ProofFixture struct {
	SolidityProof       [8]string `json:"solidity_proof"`
	ArchiveOriginalRoot string    `json:"archive_original_root"`
	ArchiveReplicaRoot  string    `json:"archive_replica_root"`
	PublicKey           string    `json:"public_key"`
	ChallengeRandomness string    `json:"challenge_randomness"`
}

// ExportProofFixture generates a deterministic proof fixture.
func ExportProofFixture(keysDir string) ([]byte, error) {
	fmt.Println("Compiling archive_muri circuit...")
	ccs, err := setup.CompileCircuit(&ArchiveMURICircuit{})
	if err != nil {
		return nil, fmt.Errorf("compile circuit: %w", err)
	}

	fmt.Println("Loading keys...")
	pk, vk, err := setup.LoadKeys(keysDir, "archive_muri")
	if err != nil {
		return nil, fmt.Errorf("load keys: %w", err)
	}

	// Create deterministic test archive
	files := make([][]byte, C)
	for i := 0; i < C; i++ {
		files[i] = make([]byte, FileSize*3) // 3 chunks per file
		for j := range files[i] {
			files[i][j] = byte((i*256 + j) % 256)
		}
	}

	origTree, err := archive.BuildOriginalArchiveTree(files)
	if err != nil {
		return nil, fmt.Errorf("build original tree: %w", err)
	}

	totalChunks := archive.TotalRealChunks(origTree.Metas)
	allChunks := getAllChunks(files)
	origElements := chunksToFrElements(allChunks)

	secretKey := new(big.Int).SetUint64(12345)
	var skFr fr.Element
	skFr.SetBigInt(secretKey)
	secretKey = new(big.Int)
	skFr.BigInt(secretKey)

	pubKey := crypto.DerivePublicKey(secretKey)
	archiveOrigRoot := archive.ComputeArchiveOriginalRoot(origTree.SlotTree.Root, totalChunks)
	globalR := crypto.DeriveGlobalR(pubKey, archiveOrigRoot)

	sealResult := muri.SealArchive(origElements, globalR)

	replicaTree, err := archive.BuildReplicaArchiveTree(sealResult.Enc2, origTree.Metas)
	if err != nil {
		return nil, fmt.Errorf("build replica tree: %w", err)
	}

	encChunks := frElementsToChunkBytes(sealResult.Enc2, totalChunks)
	origChunks := frElementsToChunkBytes(frSliceFromElements(origElements), totalChunks)

	challengeRandomness := new(big.Int).SetUint64(42)
	var crFr fr.Element
	crFr.SetBigInt(challengeRandomness)
	challengeRandomness = new(big.Int)
	crFr.BigInt(challengeRandomness)

	result, err := PrepareWitness(
		pubKey, challengeRandomness,
		origTree, replicaTree,
		origElements, sealResult.Enc2, sealResult.Enc1,
		origChunks, encChunks, globalR,
	)
	if err != nil {
		return nil, fmt.Errorf("prepare witness: %w", err)
	}

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

	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}
	fmt.Println("Proof verified successfully in Go!")

	bn254Proof := proof.(*groth16bn254.Proof)
	aX, aY := new(big.Int), new(big.Int)
	bn254Proof.Ar.X.BigInt(aX)
	bn254Proof.Ar.Y.BigInt(aY)
	bX0, bX1, bY0, bY1 := new(big.Int), new(big.Int), new(big.Int), new(big.Int)
	bn254Proof.Bs.X.A0.BigInt(bX0)
	bn254Proof.Bs.X.A1.BigInt(bX1)
	bn254Proof.Bs.Y.A0.BigInt(bY0)
	bn254Proof.Bs.Y.A1.BigInt(bY1)
	cX, cY := new(big.Int), new(big.Int)
	bn254Proof.Krs.X.BigInt(cX)
	bn254Proof.Krs.Y.BigInt(cY)
	solidityProof := [8]*big.Int{aX, aY, bX1, bX0, bY1, bY0, cX, cY}

	fixture := ProofFixture{
		ArchiveOriginalRoot: fmt.Sprintf("0x%064x", archiveOrigRoot),
		ArchiveReplicaRoot:  fmt.Sprintf("0x%064x", replicaTree.Root()),
		PublicKey:           fmt.Sprintf("0x%064x", pubKey),
		ChallengeRandomness: fmt.Sprintf("0x%064x", challengeRandomness),
	}
	for i := 0; i < 8; i++ {
		fixture.SolidityProof[i] = fmt.Sprintf("0x%064x", solidityProof[i])
	}

	jsonOut, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal fixture: %w", err)
	}

	fmt.Println("\n=== PROOF FIXTURE (JSON) ===")
	fmt.Println(string(jsonOut))

	fmt.Println("\n=== PUBLIC WITNESS ORDER ===")
	fmt.Println("[archiveOriginalRoot, archiveReplicaRoot, publicKey, challengeRandomness]")
	var pubWitBuf bytes.Buffer
	_, err = publicWitness.WriteTo(&pubWitBuf)
	if err != nil {
		return nil, fmt.Errorf("write public witness: %w", err)
	}
	fmt.Printf("Public witness size: %d bytes\n", pubWitBuf.Len())

	return jsonOut, nil
}

func getAllChunks(files [][]byte) [][]byte {
	var all [][]byte
	for _, f := range files {
		all = append(all, merkle.SplitIntoChunks(f, FileSize)...)
	}
	return all
}

func chunksToFrElements(chunks [][]byte) []fr.Element {
	totalElements := len(chunks) * ElementsPerChunk
	elements := make([]fr.Element, totalElements)
	for c, chunk := range chunks {
		for e := 0; e < ElementsPerChunk; e++ {
			start := e * ElementSize
			end := start + ElementSize
			if end > len(chunk) {
				end = len(chunk)
			}
			if start < len(chunk) {
				buf := make([]byte, ElementSize)
				copy(buf, chunk[start:end])
				elements[c*ElementsPerChunk+e].SetBytes(buf)
			}
		}
	}
	return elements
}

func frElementsToChunkBytes(elements []fr.Element, totalChunks int) [][]byte {
	chunks := make([][]byte, totalChunks)
	for c := 0; c < totalChunks; c++ {
		buf := make([]byte, ElementsPerChunk*ElementSize)
		for e := 0; e < ElementsPerChunk; e++ {
			b := elements[c*ElementsPerChunk+e].Bytes()
			copy(buf[e*ElementSize:(e+1)*ElementSize], b[32-ElementSize:])
		}
		chunks[c] = buf
	}
	return chunks
}

func frSliceFromElements(elements []fr.Element) []fr.Element {
	return elements
}

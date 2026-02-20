package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/MuriData/muri-zkproof/circuits"
	"github.com/MuriData/muri-zkproof/config"
	"github.com/MuriData/muri-zkproof/utils"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/twistededwards/eddsa"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

// ProofFixture holds all values needed for Solidity tests
type ProofFixture struct {
	SolidityProof [8]string `json:"solidity_proof"`
	Randomness    string    `json:"randomness"`
	RootHash      string    `json:"root_hash"`
	Commitment    string    `json:"commitment"`
	PublicKeyX    string    `json:"public_key_x"`
	PublicKeyY    string    `json:"public_key_y"`
}

func main() {
	// 1. Compile the circuit
	fmt.Println("Compiling circuit...")
	var poiCircuit circuits.PoICircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &poiCircuit)
	if err != nil {
		log.Fatal(err)
	}

	// 2. Load proving and verifying keys
	fmt.Println("Loading keys...")
	pk := groth16.NewProvingKey(ecc.BN254)
	f, err := os.OpenFile("poi_prover.key", os.O_RDONLY, os.ModeTemporary)
	if err != nil {
		log.Fatal("Cannot open poi_prover.key. Run 'go run compile.go' first:", err)
	}
	_, err = pk.ReadFrom(f)
	if err != nil {
		log.Fatal(err)
	}
	f.Close()

	vk := groth16.NewVerifyingKey(ecc.BN254)
	f, err = os.OpenFile("poi_verifier.key", os.O_RDONLY, os.ModeTemporary)
	if err != nil {
		log.Fatal(err)
	}
	_, err = vk.ReadFrom(f)
	if err != nil {
		log.Fatal(err)
	}
	f.Close()

	// 3. Create a small deterministic test file (16KB, single chunk)
	testFileData := make([]byte, config.FileSize)
	for i := range testFileData {
		testFileData[i] = byte(i % 256)
	}

	chunks := utils.SplitIntoChunks(testFileData)
	fmt.Printf("Chunks: %d\n", len(chunks))

	// 4. Use a deterministic randomness
	randomness := new(big.Int).SetUint64(42)
	var randFr fr.Element
	randFr.SetBigInt(randomness)
	randomness = new(big.Int)
	randFr.BigInt(randomness)

	// 5. Generate Merkle tree
	merkleTree := utils.GenerateMerkleTree(chunks)
	fmt.Printf("Merkle root: 0x%x\n", merkleTree.GetRoot().Bytes())
	fmt.Printf("Leaves: %d, Height: %d\n", merkleTree.GetLeafCount(), merkleTree.GetHeight())

	// 6. Deterministic leaf selection
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

	leafCount := len(chunks)
	testData := chunks[int(chunkIndex)%leafCount]
	fmt.Printf("Selected chunk index: %d\n", chunkIndex)

	// 7. Compute message hash = H(data * randomness) and sign it
	msg := utils.Hash(testData, randomness)
	fmt.Printf("Message hash: 0x%x\n", msg.Bytes())

	// 8. Generate EdDSA key pair and sign the message
	signer, err := utils.GenerateSigner()
	if err != nil {
		log.Fatal(err)
	}

	publicKey := signer.Public()
	sig, err := utils.Sign(msg.Bytes(), signer)
	if err != nil {
		log.Fatal(err)
	}

	// 9. Commitment = signature R.X (nonce point X coordinate)
	commitment, err := utils.SignatureRX(sig)
	if err != nil {
		log.Fatal("Failed to extract signature R.X:", err)
	}
	fmt.Printf("Commitment (sig R.X): 0x%x\n", commitment.Bytes())

	// Extract X and Y from the public key using gnark-crypto's native eddsa type
	pkBytes := publicKey.Bytes()
	var typedPK eddsa.PublicKey
	_, err = typedPK.SetBytes(pkBytes)
	if err != nil {
		log.Fatal("Failed to parse public key:", err)
	}
	pubKeyX := new(big.Int)
	pubKeyY := new(big.Int)
	typedPK.A.X.BigInt(pubKeyX)
	typedPK.A.Y.BigInt(pubKeyY)

	fmt.Printf("Public Key X: 0x%064x\n", pubKeyX)
	fmt.Printf("Public Key Y: 0x%064x\n", pubKeyY)

	// 10. Prepare Merkle proof
	merkleProof, directions, err := merkleTree.GetMerkleProof(int(chunkIndex))
	if err != nil {
		log.Fatal(err)
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
			proofDirections[i] = 0
		} else {
			proofDirections[i] = 1
		}
	}
	for i := len(merkleProof); i < config.MaxTreeDepth; i++ {
		proofPath[i] = 0
		proofDirections[i] = 0
	}

	// 11. Build witness
	assignment := circuits.PoICircuit{}
	assignment.Bytes = utils.Bytes2Field(testData)
	assignment.Commitment = commitment
	assignment.Randomness = randomness
	assignment.PublicKey.Assign(tedwards.BN254, pkBytes)
	assignment.Signature.Assign(tedwards.BN254, sig)
	assignment.RootHash = merkleTree.GetRoot()
	assignment.MerkleProof.RootHash = merkleTree.GetRoot()
	assignment.MerkleProof.LeafValue = merkleTree.Leaves[chunkIndex].Hash
	assignment.MerkleProof.ProofPath = proofPath
	assignment.MerkleProof.Directions = proofDirections

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		log.Fatal("Failed to create witness:", err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		log.Fatal(err)
	}

	// 12. Generate proof
	fmt.Println("Generating proof...")
	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		log.Fatal("Proof generation failed:", err)
	}

	// 13. Verify proof in Go
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		log.Fatal("Proof verification failed:", err)
	}
	fmt.Println("Proof verified successfully in Go!")

	// 14. Extract proof points for Solidity
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
		RootHash:   fmt.Sprintf("0x%064x", merkleTree.GetRoot()),
		Commitment: fmt.Sprintf("0x%064x", commitment),
		PublicKeyX: fmt.Sprintf("0x%064x", pubKeyX),
		PublicKeyY: fmt.Sprintf("0x%064x", pubKeyY),
	}
	for i := 0; i < 8; i++ {
		fixture.SolidityProof[i] = fmt.Sprintf("0x%064x", solidityProof[i])
	}

	// Output JSON
	jsonOut, _ := json.MarshalIndent(fixture, "", "  ")
	fmt.Println("\n=== PROOF FIXTURE (JSON) ===")
	fmt.Println(string(jsonOut))

	// Output Solidity constants
	fmt.Println("\n=== SOLIDITY CONSTANTS ===")
	fmt.Printf("    // Public inputs\n")
	fmt.Printf("    uint256 constant ZK_RANDOMNESS = %s;\n", fixture.Randomness)
	fmt.Printf("    uint256 constant ZK_FILE_ROOT = %s;\n", fixture.RootHash)
	fmt.Printf("    bytes32 constant ZK_COMMITMENT = bytes32(%s);\n", fixture.Commitment)
	fmt.Printf("    uint256 constant ZK_PUB_KEY_X = %s;\n", fixture.PublicKeyX)
	fmt.Printf("    uint256 constant ZK_PUB_KEY_Y = %s;\n", fixture.PublicKeyY)
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

	// Write fixture
	os.WriteFile("proof_fixture.json", jsonOut, 0644)
	fmt.Println("\nFixture written to proof_fixture.json")

	// Public witness info
	fmt.Println("\n=== PUBLIC WITNESS ORDER ===")
	fmt.Println("In gnark circuit (= Solidity order): [commitment, randomness, publicKey.A.X, publicKey.A.Y, rootHash]")
	var pubWitBuf bytes.Buffer
	_, err = publicWitness.WriteTo(&pubWitBuf)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("Public witness size: %d bytes\n", pubWitBuf.Len())

	// gnark orders: commitment(0), randomness(1), pubkey.A.X(2), pubkey.A.Y(3), rootHash(4)
	// gnark's ExportSolidity maps gnark indices [0..4] to Solidity indices in the same order
	fmt.Println("\ngnark public input order (from circuit struct tags):")
	fmt.Println("  [0] commitment")
	fmt.Println("  [1] randomness")
	fmt.Println("  [2] publicKey.A.X")
	fmt.Println("  [3] publicKey.A.Y")
	fmt.Println("  [4] rootHash")
	fmt.Println("\nMake sure Market.sol's publicInputs array matches this order!")
}

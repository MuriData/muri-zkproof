package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"os"

	"github.com/MuriData/muri-zkproof/circuits"
	"github.com/MuriData/muri-zkproof/config"
	"github.com/MuriData/muri-zkproof/utils"
	"github.com/consensys/gnark-crypto/ecc"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func generateRandomData(size int) ([]byte, error) {
	data := make([]byte, size)
	_, err := rand.Read(data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func main() {
	var poiCircuit circuits.PoICircuit
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &poiCircuit)
	if err != nil {
		log.Fatal(err)
	}

	// 1. One time setup
	// pk, vk, err := groth16.Setup(r1cs)
	// if err != nil {
	// 	log.Fatal(err)
	// }

	pk := groth16.NewProvingKey(ecc.BN254)
	f, err := os.OpenFile("poi_prover.key", os.O_RDONLY, os.ModeTemporary)
	if err != nil {
		log.Fatal(err)
	}
	_, err = pk.ReadFrom(f)
	if err != nil {
		log.Fatal(err)
	}

	vk := groth16.NewVerifyingKey(ecc.BN254)
	f, err = os.OpenFile("poi_verifier.key", os.O_RDONLY, os.ModeTemporary)
	if err != nil {
		log.Fatal(err)
	}
	_, err = vk.ReadFrom(f)
	if err != nil {
		log.Fatal(err)
	}

	// Generate random test data (128 KB = 8 chunks of 16 KB)
	testFileSize := 8 * config.FileSize
	wholeFileData, err := generateRandomData(testFileSize)
	if err != nil {
		log.Fatal("Failed to generate random data:", err)
	}
	chunks := utils.SplitIntoChunks(wholeFileData)
	fmt.Printf("Generated %d bytes of random data (%d chunks)\n", testFileSize, len(chunks))
	leafCount := len(chunks)

	// Generate random scalar field element for both commitment and chunk selection
	randomness, err := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	if err != nil {
		log.Fatal("Failed to generate randomness:", err)
	}

	// Generate Merkle tree from the whole file data
	fmt.Println("\n=== Generating Merkle Tree ===")
	merkleTree := utils.GenerateMerkleTree(chunks)

	fmt.Printf("Merkle Tree Statistics:\n")
	fmt.Printf("- Root Hash: 0x%x\n", merkleTree.GetRoot().Bytes())
	fmt.Printf("- Number of leaves: %d\n", merkleTree.GetLeafCount())
	fmt.Printf("- Tree height: %d\n", merkleTree.GetHeight())
	fmt.Printf("- File size: %d bytes\n", merkleTree.FileSize)
	fmt.Printf("- Chunk count: %d\n", merkleTree.ChunkCount)

	fmt.Println("\n=== Merkle Tree Structure ===")
	fmt.Println(merkleTree.String())

	// Direction rule (circuit): 0 = sibling on right, 1 = sibling on left.

	// Compute tree height (excluding root level) but capped by MaxTreeDepth
	treeHeight := merkleTree.GetHeight() - 1
	if treeHeight > config.MaxTreeDepth {
		treeHeight = config.MaxTreeDepth
	}

	fmt.Printf("Debug: Tree height = %d, using %d bits\n", treeHeight, treeHeight)

	// Debug: print randomness bits
	fmt.Printf("Debug: Randomness bits (first %d): ", treeHeight)
	for i := 0; i < treeHeight; i++ {
		fmt.Printf("%d", randomness.Bit(i))
	}
	fmt.Println()

	// Build leaf index from randomness bits: leafBit = 1 - randBit
	computeIndex := func(r *big.Int, depth int) int64 {
		var idx int64
		for i := 0; i < depth; i++ {
			bit := r.Bit(i) // 0 or 1
			leafBit := 1 - int(bit)
			idx |= int64(leafBit) << i
		}
		return idx
	}

	chunkIndex := computeIndex(randomness, treeHeight)

	fmt.Printf("Randomness used: %s\n", randomness.String())
	fmt.Printf("Selected chunk index (computed): %d (binary: ", chunkIndex)
	for i := treeHeight - 1; i >= 0; i-- {
		if (chunkIndex>>i)&1 == 1 {
			fmt.Printf("1")
		} else {
			fmt.Printf("0")
		}
	}
	fmt.Println(")")

	// Retrieve Merkle proof for that index
	merkleProof, directions, err := merkleTree.GetMerkleProof(int(chunkIndex))
	if err != nil {
		log.Fatal(err)
	}

	// Cap proof length to MaxTreeDepth (tree is perfect power-of-two so len matches treeHeight)
	if len(merkleProof) > config.MaxTreeDepth {
		merkleProof = merkleProof[:config.MaxTreeDepth]
		directions = directions[:config.MaxTreeDepth]
	}

	testData := chunks[int(chunkIndex)%leafCount] // repeated padding wraps around

	fmt.Printf("Proof depth (levels): %d\n", len(merkleProof))

	// Calculate the Poseidon2 hash outside the circuit directly from the selected chunk
	calculatedCommitment := utils.Hash(testData, randomness)
	fmt.Printf("Calculated Poseidon2 hash: 0x%x\n", calculatedCommitment.Bytes())

	signer, err := utils.GenerateSigner()
	if err != nil {
		log.Fatal(err)
	}

	publicKey := signer.Public()

	fmt.Printf("\nPublic key (hex): 0x%x\n", publicKey.Bytes())

	signature, err := utils.Sign(calculatedCommitment.Bytes(), signer)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Signature (hex): 0x%x\n", signature)

	// Prepare Merkle proof data for the circuit
	fmt.Println("\n=== Preparing Circuit Assignment ===")

	// Create arrays for proof path and directions with proper padding
	var proofPath [config.MaxTreeDepth]frontend.Variable
	var proofDirections [config.MaxTreeDepth]frontend.Variable

	// Fill in the actual proof data (up to actual proof length, but cap at MaxTreeDepth)
	for i := 0; i < len(merkleProof) && i < config.MaxTreeDepth; i++ {
		proofPath[i] = merkleProof[i]
		if directions[i] {
			proofDirections[i] = 0 // sibling on right -> 0
		} else {
			proofDirections[i] = 1 // sibling on left -> 1
		}
	}

	// Fill remaining slots with zeros for any unused entries
	for i := len(merkleProof); i < config.MaxTreeDepth; i++ {
		proofPath[i] = 0
		proofDirections[i] = 0
	}

	fmt.Printf("Merkle tree leaf hash: 0x%x\n", merkleTree.Leaves[chunkIndex].Hash.Bytes())

	assignment := circuits.PoICircuit{}
	assignment.Bytes = utils.Bytes2Field(testData)
	assignment.Commitment = calculatedCommitment
	assignment.Randomness = randomness
	assignment.PublicKey.Assign(tedwards.BN254, publicKey.Bytes())
	assignment.Signature.Assign(tedwards.BN254, signature)
	assignment.RootHash = merkleTree.GetRoot()

	// Assign Merkle proof data
	assignment.MerkleProof.RootHash = merkleTree.GetRoot()
	assignment.MerkleProof.LeafValue = merkleTree.Leaves[chunkIndex].Hash
	assignment.MerkleProof.ProofPath = proofPath
	assignment.MerkleProof.Directions = proofDirections

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		log.Fatal(err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		log.Fatal(err)
	}

	// 2. Proof creation
	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		log.Fatal(err)
	}

	// 3. Proof verification
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("\n=== ZK Proof Verification Successful! ===")
}

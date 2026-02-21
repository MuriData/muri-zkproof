package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"os"

	"github.com/MuriData/muri-zkproof/circuits"
	"github.com/MuriData/muri-zkproof/config"
	"github.com/MuriData/muri-zkproof/utils"
	"github.com/consensys/gnark-crypto/ecc"
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

	// 1. Load proving and verifying keys
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

	// 2. Generate random test data (128 KB = 8 chunks of 16 KB)
	testFileSize := 8 * config.FileSize
	wholeFileData, err := generateRandomData(testFileSize)
	if err != nil {
		log.Fatal("Failed to generate random data:", err)
	}
	chunks := utils.SplitIntoChunks(wholeFileData)
	fmt.Printf("Generated %d bytes of random data (%d chunks)\n", testFileSize, len(chunks))

	// 3. Generate randomness and secret key
	randomness, err := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	if err != nil {
		log.Fatal("Failed to generate randomness:", err)
	}

	secretKey, err := utils.GenerateSecretKey()
	if err != nil {
		log.Fatal(err)
	}

	// 4. Build Merkle tree and prepare the full witness
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

	result, err := utils.PrepareWitness(secretKey, randomness, chunks, merkleTree)
	if err != nil {
		log.Fatal("Failed to prepare witness:", err)
	}

	fmt.Printf("Randomness: 0x%x\n", randomness.Bytes())
	fmt.Printf("Selected chunk index: %d\n", result.ChunkIndex)
	fmt.Printf("Secret key: 0x%x\n", secretKey.Bytes())
	fmt.Printf("Public key (H(sk)): 0x%x\n", result.PublicKey.Bytes())
	fmt.Printf("Message hash: 0x%x\n", result.Msg.Bytes())
	fmt.Printf("Commitment: 0x%x\n", result.Commitment.Bytes())

	// 5. Create witness and generate proof
	witness, err := frontend.NewWitness(&result.Assignment, ecc.BN254.ScalarField())
	if err != nil {
		log.Fatal(err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		log.Fatal(err)
	}

	proof, err := groth16.Prove(r1cs, pk, witness)
	if err != nil {
		log.Fatal(err)
	}

	// 6. Verify proof
	err = groth16.Verify(proof, vk, publicWitness)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println("\n=== ZK Proof Verification Successful! ===")
}

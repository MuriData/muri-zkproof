package keyleak

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/MuriData/muri-zkproof/pkg/crypto"
	"github.com/MuriData/muri-zkproof/pkg/setup"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	plonkbn254 "github.com/consensys/gnark/backend/plonk/bn254"
	"github.com/consensys/gnark/frontend"
)

// ProofFixture holds all values needed for Solidity tests.
type ProofFixture struct {
	SolidityProof   string `json:"solidity_proof"`
	PublicKey       string `json:"public_key"`
	ReporterAddress string `json:"reporter_address"`
}

// ExportProofFixture generates a deterministic PLONK proof fixture for Solidity tests.
// keysDir is the directory containing the proving and verifying keys.
func ExportProofFixture(keysDir string) ([]byte, error) {
	// 1. Compile the circuit (SCS for PLONK)
	fmt.Println("Compiling keyleak circuit (PLONK/SCS)...")
	ccs, err := setup.CompileCircuitForBackend(&KeyLeakCircuit{}, setup.PlonkBackend)
	if err != nil {
		return nil, fmt.Errorf("compile circuit: %w", err)
	}

	// 2. Load PLONK proving and verifying keys
	fmt.Println("Loading PLONK keys...")
	pk, vk, err := setup.LoadPlonkKeys(keysDir, "keyleak")
	if err != nil {
		return nil, fmt.Errorf("load keys: %w", err)
	}

	// 3. Deterministic witness values
	secretKey := new(big.Int).SetUint64(12345)
	publicKey := crypto.DerivePublicKey(secretKey)
	reporterAddress := new(big.Int).SetUint64(0xDEAD)

	fmt.Printf("Secret key: %d\n", secretKey)
	fmt.Printf("Public key (H(sk)): 0x%064x\n", publicKey)
	fmt.Printf("Reporter address: 0x%x\n", reporterAddress)

	assignment := KeyLeakCircuit{
		PublicKey:       publicKey,
		ReporterAddress: reporterAddress,
		SecretKey:       secretKey,
	}

	// 4. Create witness and generate proof
	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("create witness: %w", err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		return nil, fmt.Errorf("extract public witness: %w", err)
	}

	fmt.Println("Generating PLONK proof...")
	proof, err := plonk.Prove(ccs, pk, witness)
	if err != nil {
		return nil, fmt.Errorf("prove: %w", err)
	}

	// 5. Verify proof in Go
	err = plonk.Verify(proof, vk, publicWitness)
	if err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}
	fmt.Println("PLONK proof verified successfully in Go!")

	// 6. Marshal proof for Solidity
	bn254Proof := proof.(*plonkbn254.Proof)
	solidityBytes := bn254Proof.MarshalSolidity()

	fixture := ProofFixture{
		SolidityProof:   "0x" + hex.EncodeToString(solidityBytes),
		PublicKey:       fmt.Sprintf("0x%064x", publicKey),
		ReporterAddress: fmt.Sprintf("0x%064x", reporterAddress),
	}

	jsonOut, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal fixture: %w", err)
	}

	// Print diagnostic info
	fmt.Println("\n=== PROOF FIXTURE (JSON) ===")
	fmt.Println(string(jsonOut))

	fmt.Println("\n=== SOLIDITY CONSTANTS ===")
	fmt.Printf("    uint256 constant ZK_PUB_KEY = %s;\n", fixture.PublicKey)
	fmt.Printf("    uint256 constant ZK_REPORTER = %s;\n", fixture.ReporterAddress)
	fmt.Printf("    bytes constant ZK_PROOF = hex\"%s\";\n", hex.EncodeToString(solidityBytes))

	fmt.Println("\n=== PUBLIC WITNESS ORDER ===")
	fmt.Println("In gnark circuit (= Solidity order): [publicKey, reporterAddress]")
	fmt.Println("\nPLONK Solidity verifier signature:")
	fmt.Println("  function Verify(bytes calldata proof, uint256[] calldata public_inputs) public view returns(bool)")

	return jsonOut, nil
}

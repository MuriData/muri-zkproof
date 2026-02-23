package keyleak_test

import (
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/MuriData/muri-zkproof/circuits/keyleak"
	"github.com/MuriData/muri-zkproof/pkg/crypto"
	"github.com/MuriData/muri-zkproof/pkg/setup"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/test/unsafekzg"
)

// TestKeyLeakCircuitEndToEnd compiles the circuit with SCS, performs an
// unsafe PLONK setup, generates a proof, and verifies it.
func TestKeyLeakCircuitEndToEnd(t *testing.T) {
	// 1. Compile (SCS for PLONK)
	ccs, err := setup.CompileCircuitForBackend(&keyleak.KeyLeakCircuit{}, setup.PlonkBackend)
	if err != nil {
		t.Fatalf("compile circuit: %v", err)
	}

	// 2. Generate unsafe KZG SRS and run PLONK setup
	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		t.Fatalf("generate SRS: %v", err)
	}

	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		t.Fatalf("plonk setup: %v", err)
	}

	// 3. Generate a random secret key and derive the public key
	secretKey, err := crypto.GenerateSecretKey()
	if err != nil {
		t.Fatalf("generate secret key: %v", err)
	}
	publicKey := crypto.DerivePublicKey(secretKey)
	reporterAddress := new(big.Int).SetUint64(0xCAFE)

	t.Logf("Secret key: 0x%064x", secretKey)
	t.Logf("Public key: 0x%064x", publicKey)
	t.Logf("Reporter:   0x%x", reporterAddress)

	// 4. Build witness
	assignment := keyleak.KeyLeakCircuit{
		PublicKey:       publicKey,
		ReporterAddress: reporterAddress,
		SecretKey:       secretKey,
	}

	witness, err := frontend.NewWitness(&assignment, ecc.BN254.ScalarField())
	if err != nil {
		t.Fatalf("create witness: %v", err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		t.Fatalf("extract public witness: %v", err)
	}

	// 5. Prove
	proof, err := plonk.Prove(ccs, pk, witness)
	if err != nil {
		t.Fatalf("prove: %v", err)
	}

	// 6. Verify
	err = plonk.Verify(proof, vk, publicWitness)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	t.Log("PLONK keyleak proof verified successfully!")
}

// TestKeyLeakExportFixture generates a deterministic fixture and verifies
// that it round-trips through JSON.
func TestKeyLeakExportFixture(t *testing.T) {
	// 1. Compile and dev setup
	ccs, err := setup.CompileCircuitForBackend(&keyleak.KeyLeakCircuit{}, setup.PlonkBackend)
	if err != nil {
		t.Fatalf("compile circuit: %v", err)
	}

	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		t.Fatalf("generate SRS: %v", err)
	}

	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		t.Fatalf("plonk setup: %v", err)
	}

	// 2. Write keys to temp directory
	tmpDir := t.TempDir()
	if err := setup.ExportPlonkKeys(pk, vk, tmpDir, "keyleak"); err != nil {
		t.Fatalf("export keys: %v", err)
	}

	// 3. Generate fixture
	jsonOut, err := keyleak.ExportProofFixture(tmpDir)
	if err != nil {
		t.Fatalf("export proof fixture: %v", err)
	}

	// 4. Verify JSON round-trips
	var fixture keyleak.ProofFixture
	if err := json.Unmarshal(jsonOut, &fixture); err != nil {
		t.Fatalf("unmarshal fixture: %v", err)
	}

	if fixture.SolidityProof == "" {
		t.Fatal("fixture solidity_proof is empty")
	}
	if fixture.PublicKey == "" {
		t.Fatal("fixture public_key is empty")
	}
	if fixture.ReporterAddress == "" {
		t.Fatal("fixture reporter_address is empty")
	}

	jsonRoundTrip, err := json.MarshalIndent(fixture, "", "  ")
	if err != nil {
		t.Fatalf("re-marshal fixture: %v", err)
	}
	if string(jsonRoundTrip) != string(jsonOut) {
		t.Fatal("fixture JSON round-trip mismatch")
	}

	fmt.Println("Keyleak fixture round-trip OK")
}

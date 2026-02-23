package setup

import (
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/bits"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"github.com/consensys/gnark/backend/plonk"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/frontend/cs/scs"
	"github.com/consensys/gnark/test/unsafekzg"
)

// Backend selects which proof system to use for a circuit.
type Backend int

const (
	Groth16Backend Backend = iota
	PlonkBackend
)

// CompileCircuit compiles a gnark circuit into a constraint system.
func CompileCircuit(circuit frontend.Circuit) (constraint.ConstraintSystem, error) {
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		return nil, fmt.Errorf("compile circuit: %w", err)
	}
	return ccs, nil
}

// DevSetup performs a single-party trusted setup (NOT for production).
// It writes the proving key, verifying key, and Solidity verifier to outputDir.
func DevSetup(circuit frontend.Circuit, outputDir, circuitName string) error {
	fmt.Println("================================================================")
	fmt.Println("  WARNING: Single-party setup (1-of-1 trust assumption)")
	fmt.Println("  DO NOT use these keys in production.")
	fmt.Printf("  For production, run: go run ./cmd/compile %s ceremony --help\n", circuitName)
	fmt.Println("================================================================")

	ccs, err := CompileCircuit(circuit)
	if err != nil {
		return err
	}

	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		return fmt.Errorf("groth16 setup: %w", err)
	}

	return ExportKeys(pk, vk, outputDir, circuitName)
}

// ExportKeys writes the proving key, verifying key, and Solidity verifier to outputDir.
// Files are named: <circuitName>_prover.key, <circuitName>_verifier.key, <circuitName>_verifier.sol
func ExportKeys(pk groth16.ProvingKey, vk groth16.VerifyingKey, outputDir, circuitName string) error {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	solPath := filepath.Join(outputDir, circuitName+"_verifier.sol")
	f, err := os.Create(solPath)
	if err != nil {
		return fmt.Errorf("create solidity verifier: %w", err)
	}
	if err := vk.ExportSolidity(f); err != nil {
		f.Close()
		return fmt.Errorf("export solidity verifier: %w", err)
	}
	f.Close()

	vkPath := filepath.Join(outputDir, circuitName+"_verifier.key")
	saveObject(vkPath, vk)

	pkPath := filepath.Join(outputDir, circuitName+"_prover.key")
	saveObject(pkPath, pk)

	fmt.Printf("Exported: %s, %s, %s\n", pkPath, vkPath, solPath)
	return nil
}

// LoadKeys loads the proving and verifying keys from the given directory.
func LoadKeys(dir, circuitName string) (groth16.ProvingKey, groth16.VerifyingKey, error) {
	pk := groth16.NewProvingKey(ecc.BN254)
	pkPath := filepath.Join(dir, circuitName+"_prover.key")
	f, err := os.Open(pkPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open proving key: %w", err)
	}
	if _, err := pk.ReadFrom(f); err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("read proving key: %w", err)
	}
	f.Close()

	vk := groth16.NewVerifyingKey(ecc.BN254)
	vkPath := filepath.Join(dir, circuitName+"_verifier.key")
	f, err = os.Open(vkPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open verifying key: %w", err)
	}
	if _, err := vk.ReadFrom(f); err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("read verifying key: %w", err)
	}
	f.Close()

	return pk, vk, nil
}

// ─── PLONK ───────────────────────────────────────────────────────────────────

// CompileCircuitForBackend compiles a circuit using the builder for the given backend.
func CompileCircuitForBackend(circuit frontend.Circuit, b Backend) (constraint.ConstraintSystem, error) {
	var builder frontend.NewBuilder
	switch b {
	case Groth16Backend:
		builder = r1cs.NewBuilder
	case PlonkBackend:
		builder = scs.NewBuilder
	default:
		return nil, fmt.Errorf("unknown backend: %d", b)
	}
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), builder, circuit)
	if err != nil {
		return nil, fmt.Errorf("compile circuit: %w", err)
	}
	return ccs, nil
}

// PlonkDevSetup performs a single-party PLONK setup (NOT for production).
// It writes the proving key, verifying key, and Solidity verifier to outputDir.
func PlonkDevSetup(circuit frontend.Circuit, outputDir, circuitName string) error {
	fmt.Println("================================================================")
	fmt.Println("  WARNING: Unsafe KZG SRS (1-of-1 trust assumption)")
	fmt.Println("  DO NOT use these keys in production.")
	fmt.Println("  PLONK uses a universal SRS — no circuit-specific ceremony needed.")
	fmt.Println("================================================================")

	ccs, err := CompileCircuitForBackend(circuit, PlonkBackend)
	if err != nil {
		return err
	}

	srs, srsLagrange, err := unsafekzg.NewSRS(ccs)
	if err != nil {
		return fmt.Errorf("generate unsafe KZG SRS: %w", err)
	}

	pk, vk, err := plonk.Setup(ccs, srs, srsLagrange)
	if err != nil {
		return fmt.Errorf("plonk setup: %w", err)
	}

	return ExportPlonkKeys(pk, vk, outputDir, circuitName)
}

// ExportPlonkKeys writes PLONK proving key, verifying key, and Solidity verifier to outputDir.
func ExportPlonkKeys(pk plonk.ProvingKey, vk plonk.VerifyingKey, outputDir, circuitName string) error {
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	solPath := filepath.Join(outputDir, circuitName+"_verifier.sol")
	f, err := os.Create(solPath)
	if err != nil {
		return fmt.Errorf("create solidity verifier: %w", err)
	}
	if err := vk.ExportSolidity(f); err != nil {
		f.Close()
		return fmt.Errorf("export solidity verifier: %w", err)
	}
	f.Close()

	vkPath := filepath.Join(outputDir, circuitName+"_verifier.key")
	saveObject(vkPath, vk)

	pkPath := filepath.Join(outputDir, circuitName+"_prover.key")
	saveObject(pkPath, pk)

	fmt.Printf("Exported: %s, %s, %s\n", pkPath, vkPath, solPath)
	return nil
}

// LoadPlonkKeys loads PLONK proving and verifying keys from the given directory.
func LoadPlonkKeys(dir, circuitName string) (plonk.ProvingKey, plonk.VerifyingKey, error) {
	pk := plonk.NewProvingKey(ecc.BN254)
	pkPath := filepath.Join(dir, circuitName+"_prover.key")
	f, err := os.Open(pkPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open proving key: %w", err)
	}
	if _, err := pk.ReadFrom(f); err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("read proving key: %w", err)
	}
	f.Close()

	vk := plonk.NewVerifyingKey(ecc.BN254)
	vkPath := filepath.Join(dir, circuitName+"_verifier.key")
	f, err = os.Open(vkPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open verifying key: %w", err)
	}
	if _, err := vk.ReadFrom(f); err != nil {
		f.Close()
		return nil, nil, fmt.Errorf("read verifying key: %w", err)
	}
	f.Close()

	return pk, vk, nil
}

// ─── MPC Ceremony ───────────────────────────────────────────────────────────

// CeremonyDir is the default directory for ceremony files.
const CeremonyDir = "ceremony"

// CeremonyP1Init initializes Phase 1 (Powers of Tau).
func CeremonyP1Init(circuit frontend.Circuit) error {
	ensureCeremonyDir()
	ccs, err := CompileCircuit(circuit)
	if err != nil {
		return err
	}

	N := ecc.NextPowerOfTwo(uint64(ccs.GetNbConstraints()))
	fmt.Printf("Phase 1: domain size N = %d (2^%d), %d constraints\n", N, bits.Len64(N)-1, ccs.GetNbConstraints())

	p := mpcsetup.NewPhase1(N)
	path := nextContribPath("phase1")
	saveObject(path, p)
	fmt.Printf("Wrote initial Phase 1 state to %s\n", path)
	return nil
}

// CeremonyP1Contribute adds a Phase 1 contribution.
func CeremonyP1Contribute() error {
	latest := latestContrib("phase1")
	fmt.Printf("Loading %s\n", latest)

	var p mpcsetup.Phase1
	loadObject(latest, &p)

	fmt.Println("Contributing randomness to Phase 1...")
	p.Contribute()

	path := nextContribPath("phase1")
	saveObject(path, &p)
	fmt.Printf("Wrote Phase 1 contribution to %s\n", path)
	return nil
}

// CeremonyP1Verify verifies Phase 1 contributions and seals with a random beacon.
func CeremonyP1Verify(circuit frontend.Circuit, beaconHex string) error {
	beacon := parseBeacon(beaconHex)
	ccs, err := CompileCircuit(circuit)
	if err != nil {
		return err
	}
	N := ecc.NextPowerOfTwo(uint64(ccs.GetNbConstraints()))

	contribs := findContribs("phase1")
	if len(contribs) < 2 {
		return fmt.Errorf("need at least the init file + one contribution to verify")
	}

	// Skip the init file (index 0); only contributed states are passed to verify
	nContribs := len(contribs) - 1
	fmt.Printf("Verifying %d Phase 1 contribution(s)...\n", nContribs)

	phases := make([]*mpcsetup.Phase1, nContribs)
	for i, path := range contribs[1:] {
		phases[i] = new(mpcsetup.Phase1)
		loadObject(path, phases[i])
	}

	commons, err := mpcsetup.VerifyPhase1(N, beacon, phases...)
	if err != nil {
		return fmt.Errorf("Phase 1 verification FAILED: %w", err)
	}

	srsPath := filepath.Join(CeremonyDir, "srs_commons.bin")
	saveObject(srsPath, &commons)
	fmt.Printf("Phase 1 verified and sealed. SRS commons written to %s\n", srsPath)
	return nil
}

// CeremonyP2Init initializes Phase 2 (circuit-specific).
func CeremonyP2Init(circuit frontend.Circuit) error {
	ensureCeremonyDir()
	ccs, err := CompileCircuit(circuit)
	if err != nil {
		return err
	}
	r1csConcrete := ccs.(*cs_bn254.R1CS)

	srsPath := filepath.Join(CeremonyDir, "srs_commons.bin")
	var commons mpcsetup.SrsCommons
	loadObject(srsPath, &commons)

	fmt.Println("Initializing Phase 2 with circuit and SRS commons...")
	var p mpcsetup.Phase2
	p.Initialize(r1csConcrete, &commons)

	path := nextContribPath("phase2")
	saveObject(path, &p)
	fmt.Printf("Wrote initial Phase 2 state to %s\n", path)
	return nil
}

// CeremonyP2Contribute adds a Phase 2 contribution.
func CeremonyP2Contribute() error {
	latest := latestContrib("phase2")
	fmt.Printf("Loading %s\n", latest)

	var p mpcsetup.Phase2
	loadObject(latest, &p)

	fmt.Println("Contributing randomness to Phase 2...")
	p.Contribute()

	path := nextContribPath("phase2")
	saveObject(path, &p)
	fmt.Printf("Wrote Phase 2 contribution to %s\n", path)
	return nil
}

// CeremonyP2Verify verifies Phase 2 contributions, seals, and exports final keys.
func CeremonyP2Verify(circuit frontend.Circuit, beaconHex, outputDir, circuitName string) error {
	beacon := parseBeacon(beaconHex)
	ccs, err := CompileCircuit(circuit)
	if err != nil {
		return err
	}
	r1csConcrete := ccs.(*cs_bn254.R1CS)

	srsPath := filepath.Join(CeremonyDir, "srs_commons.bin")
	var commons mpcsetup.SrsCommons
	loadObject(srsPath, &commons)

	contribs := findContribs("phase2")
	if len(contribs) < 2 {
		return fmt.Errorf("need at least the init file + one contribution to verify")
	}

	nContribs := len(contribs) - 1
	fmt.Printf("Verifying %d Phase 2 contribution(s)...\n", nContribs)

	phases := make([]*mpcsetup.Phase2, nContribs)
	for i, path := range contribs[1:] {
		phases[i] = new(mpcsetup.Phase2)
		loadObject(path, phases[i])
	}

	pk, vk, err := mpcsetup.VerifyPhase2(r1csConcrete, &commons, beacon, phases...)
	if err != nil {
		return fmt.Errorf("Phase 2 verification FAILED: %w", err)
	}

	if err := ExportKeys(pk, vk, outputDir, circuitName); err != nil {
		return err
	}
	fmt.Println("Ceremony complete. Keys are production-ready.")
	return nil
}

// ─── Internal helpers ───────────────────────────────────────────────────────

func ensureCeremonyDir() {
	if err := os.MkdirAll(CeremonyDir, 0o755); err != nil {
		log.Fatal(err)
	}
}

func saveObject(path string, obj io.WriterTo) {
	f, err := os.Create(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	if _, err := obj.WriteTo(f); err != nil {
		log.Fatal(err)
	}
}

func loadObject(path string, obj io.ReaderFrom) {
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	if _, err := obj.ReadFrom(f); err != nil {
		log.Fatal(err)
	}
}

func parseBeacon(hexStr string) []byte {
	hexStr = strings.TrimPrefix(hexStr, "0x")
	b, err := hex.DecodeString(hexStr)
	if err != nil {
		log.Fatalf("invalid beacon hex: %v", err)
	}
	if len(b) < 16 {
		log.Fatal("beacon must be at least 16 bytes for sufficient entropy")
	}
	return b
}

// findContribs returns sorted paths matching ceremony/<prefix>_NNNN.bin
func findContribs(prefix string) []string {
	pattern := filepath.Join(CeremonyDir, prefix+"_????.bin")
	matches, _ := filepath.Glob(pattern)
	sort.Strings(matches)
	return matches
}

func latestContrib(prefix string) string {
	contribs := findContribs(prefix)
	if len(contribs) == 0 {
		log.Fatalf("no %s contributions found in %s/", prefix, CeremonyDir)
	}
	return contribs[len(contribs)-1]
}

func nextContribPath(prefix string) string {
	return filepath.Join(CeremonyDir, fmt.Sprintf("%s_%04d.bin", prefix, len(findContribs(prefix))))
}

package main

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

	"github.com/MuriData/muri-zkproof/circuits"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/backend/groth16/bn254/mpcsetup"
	"github.com/consensys/gnark/constraint"
	cs_bn254 "github.com/consensys/gnark/constraint/bn254"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

const ceremonyDir = "ceremony"

func main() {
	if len(os.Args) < 2 || os.Args[1] != "ceremony" {
		devSetup()
		return
	}

	if len(os.Args) < 3 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[2] {
	case "p1-init":
		ceremonyP1Init()
	case "p1-contribute":
		ceremonyP1Contribute()
	case "p1-verify":
		if len(os.Args) < 4 {
			log.Fatal("usage: go run compile.go ceremony p1-verify BEACON_HEX")
		}
		ceremonyP1Verify(os.Args[3])
	case "p2-init":
		ceremonyP2Init()
	case "p2-contribute":
		ceremonyP2Contribute()
	case "p2-verify":
		if len(os.Args) < 4 {
			log.Fatal("usage: go run compile.go ceremony p2-verify BEACON_HEX")
		}
		ceremonyP2Verify(os.Args[3])
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Usage:
  go run compile.go                             Dev mode (single-party setup, insecure)

  go run compile.go ceremony p1-init            Initialize Phase 1 (Powers of Tau)
  go run compile.go ceremony p1-contribute      Add a Phase 1 contribution
  go run compile.go ceremony p1-verify HEX      Verify Phase 1 & seal with random beacon

  go run compile.go ceremony p2-init            Initialize Phase 2 (circuit-specific)
  go run compile.go ceremony p2-contribute      Add a Phase 2 contribution
  go run compile.go ceremony p2-verify HEX      Verify Phase 2, seal & export keys

Ceremony workflow:
  1. p1-init          Coordinator creates the initial Phase 1 state
  2. p1-contribute    Each participant contributes (repeat N times)
  3. p1-verify        Coordinator verifies all & seals with a public beacon
  4. p2-init          Coordinator initializes Phase 2 with the circuit
  5. p2-contribute    Each participant contributes (repeat M times)
  6. p2-verify        Coordinator verifies all, seals, and exports final keys

Security: 1-of-N honest — if any single contributor is honest, the setup is secure.
Beacon: use a public randomness source (e.g. League of Entropy) evaluated AFTER the last contribution.`)
}

// ─── Shared helpers ─────────────────────────────────────────────────────────

func compileCircuit() constraint.ConstraintSystem {
	var c circuits.PoICircuit
	ccs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &c)
	if err != nil {
		log.Fatal(err)
	}
	return ccs
}

func exportKeys(pk groth16.ProvingKey, vk groth16.VerifyingKey) {
	f, err := os.Create("poi_verifier.sol")
	if err != nil {
		log.Fatal(err)
	}
	if err := vk.ExportSolidity(f); err != nil {
		log.Fatal(err)
	}
	f.Close()

	saveObject("poi_verifier.key", vk)
	saveObject("poi_prover.key", pk)
	fmt.Println("Exported: poi_prover.key, poi_verifier.key, poi_verifier.sol")
}

func ensureCeremonyDir() {
	if err := os.MkdirAll(ceremonyDir, 0o755); err != nil {
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
	pattern := filepath.Join(ceremonyDir, prefix+"_????.bin")
	matches, _ := filepath.Glob(pattern)
	sort.Strings(matches)
	return matches
}

func latestContrib(prefix string) string {
	contribs := findContribs(prefix)
	if len(contribs) == 0 {
		log.Fatalf("no %s contributions found in %s/", prefix, ceremonyDir)
	}
	return contribs[len(contribs)-1]
}

func nextContribPath(prefix string) string {
	return filepath.Join(ceremonyDir, fmt.Sprintf("%s_%04d.bin", prefix, len(findContribs(prefix))))
}

// ─── Dev mode ───────────────────────────────────────────────────────────────

func devSetup() {
	ccs := compileCircuit()
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		log.Fatal(err)
	}
	exportKeys(pk, vk)
}

// ─── Phase 1: Powers of Tau (circuit-independent) ───────────────────────────

func ceremonyP1Init() {
	ensureCeremonyDir()
	ccs := compileCircuit()
	N := ecc.NextPowerOfTwo(uint64(ccs.GetNbConstraints()))
	fmt.Printf("Phase 1: domain size N = %d (2^%d), %d constraints\n", N, bits.Len64(N)-1, ccs.GetNbConstraints())

	p := mpcsetup.NewPhase1(N)
	path := nextContribPath("phase1")
	saveObject(path, p)
	fmt.Printf("Wrote initial Phase 1 state to %s\n", path)
}

func ceremonyP1Contribute() {
	latest := latestContrib("phase1")
	fmt.Printf("Loading %s\n", latest)

	var p mpcsetup.Phase1
	loadObject(latest, &p)

	fmt.Println("Contributing randomness to Phase 1...")
	p.Contribute()

	path := nextContribPath("phase1")
	saveObject(path, &p)
	fmt.Printf("Wrote Phase 1 contribution to %s\n", path)
}

func ceremonyP1Verify(beaconHex string) {
	beacon := parseBeacon(beaconHex)
	ccs := compileCircuit()
	N := ecc.NextPowerOfTwo(uint64(ccs.GetNbConstraints()))

	contribs := findContribs("phase1")
	if len(contribs) < 2 {
		log.Fatal("need at least the init file + one contribution to verify")
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
		log.Fatalf("Phase 1 verification FAILED: %v", err)
	}

	srsPath := filepath.Join(ceremonyDir, "srs_commons.bin")
	saveObject(srsPath, &commons)
	fmt.Printf("Phase 1 verified and sealed. SRS commons written to %s\n", srsPath)
}

// ─── Phase 2: Circuit-specific ──────────────────────────────────────────────

func ceremonyP2Init() {
	ensureCeremonyDir()
	ccs := compileCircuit()
	r1csConcrete := ccs.(*cs_bn254.R1CS)

	srsPath := filepath.Join(ceremonyDir, "srs_commons.bin")
	var commons mpcsetup.SrsCommons
	loadObject(srsPath, &commons)

	fmt.Println("Initializing Phase 2 with circuit and SRS commons...")
	var p mpcsetup.Phase2
	p.Initialize(r1csConcrete, &commons)

	path := nextContribPath("phase2")
	saveObject(path, &p)
	fmt.Printf("Wrote initial Phase 2 state to %s\n", path)
}

func ceremonyP2Contribute() {
	latest := latestContrib("phase2")
	fmt.Printf("Loading %s\n", latest)

	var p mpcsetup.Phase2
	loadObject(latest, &p)

	fmt.Println("Contributing randomness to Phase 2...")
	p.Contribute()

	path := nextContribPath("phase2")
	saveObject(path, &p)
	fmt.Printf("Wrote Phase 2 contribution to %s\n", path)
}

func ceremonyP2Verify(beaconHex string) {
	beacon := parseBeacon(beaconHex)
	ccs := compileCircuit()
	r1csConcrete := ccs.(*cs_bn254.R1CS)

	srsPath := filepath.Join(ceremonyDir, "srs_commons.bin")
	var commons mpcsetup.SrsCommons
	loadObject(srsPath, &commons)

	contribs := findContribs("phase2")
	if len(contribs) < 2 {
		log.Fatal("need at least the init file + one contribution to verify")
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
		log.Fatalf("Phase 2 verification FAILED: %v", err)
	}

	exportKeys(pk, vk)
	fmt.Println("Ceremony complete. Keys are production-ready.")
}

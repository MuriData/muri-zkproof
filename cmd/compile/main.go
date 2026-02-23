package main

import (
	"fmt"
	"log"
	"os"

	"github.com/MuriData/muri-zkproof/circuits/keyleak"
	"github.com/MuriData/muri-zkproof/circuits/poi"
	"github.com/MuriData/muri-zkproof/pkg/setup"
	"github.com/consensys/gnark/frontend"
)

// CircuitEntry pairs a circuit constructor with its proof backend.
type CircuitEntry struct {
	NewCircuit func() frontend.Circuit
	Backend    setup.Backend
}

// circuitRegistry maps circuit names to their entries.
var circuitRegistry = map[string]CircuitEntry{
	"poi":     {NewCircuit: func() frontend.Circuit { return &poi.PoICircuit{} }, Backend: setup.Groth16Backend},
	"keyleak": {NewCircuit: func() frontend.Circuit { return &keyleak.KeyLeakCircuit{} }, Backend: setup.PlonkBackend},
}

func main() {
	if len(os.Args) < 3 {
		printUsage()
		os.Exit(1)
	}

	circuitName := os.Args[1]
	entry, ok := circuitRegistry[circuitName]
	if !ok {
		fmt.Fprintf(os.Stderr, "Unknown circuit: %s\n", circuitName)
		fmt.Fprintf(os.Stderr, "Available circuits: ")
		for name := range circuitRegistry {
			fmt.Fprintf(os.Stderr, "%s ", name)
		}
		fmt.Fprintln(os.Stderr)
		os.Exit(1)
	}

	switch os.Args[2] {
	case "dev":
		switch entry.Backend {
		case setup.Groth16Backend:
			if err := setup.DevSetup(entry.NewCircuit(), ".", circuitName); err != nil {
				log.Fatal(err)
			}
		case setup.PlonkBackend:
			if err := setup.PlonkDevSetup(entry.NewCircuit(), ".", circuitName); err != nil {
				log.Fatal(err)
			}
		}
	case "ceremony":
		if entry.Backend != setup.Groth16Backend {
			log.Fatalf("MPC ceremony is only supported for Groth16 circuits. %q uses PLONK (universal SRS).", circuitName)
		}
		if len(os.Args) < 4 {
			printUsage()
			os.Exit(1)
		}
		handleCeremony(circuitName, entry.NewCircuit)
	default:
		printUsage()
		os.Exit(1)
	}
}

func handleCeremony(circuitName string, newCircuit func() frontend.Circuit) {
	switch os.Args[3] {
	case "p1-init":
		if err := setup.CeremonyP1Init(newCircuit()); err != nil {
			log.Fatal(err)
		}
	case "p1-contribute":
		if err := setup.CeremonyP1Contribute(); err != nil {
			log.Fatal(err)
		}
	case "p1-verify":
		if len(os.Args) < 5 {
			log.Fatalf("usage: go run ./cmd/compile %s ceremony p1-verify BEACON_HEX", circuitName)
		}
		if err := setup.CeremonyP1Verify(newCircuit(), os.Args[4]); err != nil {
			log.Fatal(err)
		}
	case "p2-init":
		if err := setup.CeremonyP2Init(newCircuit()); err != nil {
			log.Fatal(err)
		}
	case "p2-contribute":
		if err := setup.CeremonyP2Contribute(); err != nil {
			log.Fatal(err)
		}
	case "p2-verify":
		if len(os.Args) < 5 {
			log.Fatalf("usage: go run ./cmd/compile %s ceremony p2-verify BEACON_HEX", circuitName)
		}
		if err := setup.CeremonyP2Verify(newCircuit(), os.Args[4], ".", circuitName); err != nil {
			log.Fatal(err)
		}
	default:
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Usage:
  go run ./cmd/compile <circuit> dev                         Dev mode (single-party/unsafe setup, NOT for production)

  go run ./cmd/compile <circuit> ceremony p1-init            Initialize Phase 1 (Powers of Tau)
  go run ./cmd/compile <circuit> ceremony p1-contribute      Add a Phase 1 contribution
  go run ./cmd/compile <circuit> ceremony p1-verify HEX      Verify Phase 1 & seal with random beacon

  go run ./cmd/compile <circuit> ceremony p2-init            Initialize Phase 2 (circuit-specific)
  go run ./cmd/compile <circuit> ceremony p2-contribute      Add a Phase 2 contribution
  go run ./cmd/compile <circuit> ceremony p2-verify HEX      Verify Phase 2, seal & export keys

Available circuits: poi (Groth16), keyleak (PLONK)

Note: MPC ceremony is only available for Groth16 circuits.
      PLONK circuits use a universal SRS and only need "dev" setup.

Ceremony workflow (Groth16 only):
  1. p1-init          Coordinator creates the initial Phase 1 state
  2. p1-contribute    Each participant contributes (repeat N times)
  3. p1-verify        Coordinator verifies all & seals with a public beacon
  4. p2-init          Coordinator initializes Phase 2 with the circuit
  5. p2-contribute    Each participant contributes (repeat M times)
  6. p2-verify        Coordinator verifies all, seals, and exports final keys

Security: 1-of-N honest — if any single contributor is honest, the setup is secure.
Beacon: use a public randomness source (e.g. League of Entropy) evaluated AFTER the last contribution.`)
}

package main

import (
	"fmt"
	"log"
	"os"

	"github.com/MuriData/muri-zkproof/circuits/fsp"
	"github.com/MuriData/muri-zkproof/circuits/keyleak"
	"github.com/MuriData/muri-zkproof/circuits/poi"
	"github.com/MuriData/muri-zkproof/pkg/setup"
)

// backendRegistry maps circuit names to their proof backends.
var backendRegistry = map[string]setup.Backend{
	"poi":     setup.Groth16Backend,
	"fsp":     setup.Groth16Backend,
	"keyleak": setup.PlonkBackend,
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	circuit := os.Args[1]

	// Check for "vk" subcommand: go run ./cmd/export <circuit> vk
	if len(os.Args) >= 3 && os.Args[2] == "vk" {
		exportVK(circuit)
		return
	}

	// Default: export proof fixture
	exportProofFixture(circuit)
}

func exportVK(circuit string) {
	backend, ok := backendRegistry[circuit]
	if !ok {
		fmt.Fprintf(os.Stderr, "Unknown circuit: %s\n", circuit)
		fmt.Fprintln(os.Stderr, "Available circuits: poi, fsp, keyleak")
		os.Exit(1)
	}

	outPath := circuit + "_vk.sol"

	switch backend {
	case setup.Groth16Backend:
		_, vk, err := setup.LoadKeys(".", circuit)
		if err != nil {
			log.Fatalf("load keys: %v", err)
		}
		f, err := os.Create(outPath)
		if err != nil {
			log.Fatalf("create file: %v", err)
		}
		if err := setup.ExportGroth16VKSolidity(vk, f, circuit); err != nil {
			f.Close()
			log.Fatalf("export VK: %v", err)
		}
		f.Close()

	case setup.PlonkBackend:
		_, vk, err := setup.LoadPlonkKeys(".", circuit)
		if err != nil {
			log.Fatalf("load keys: %v", err)
		}
		f, err := os.Create(outPath)
		if err != nil {
			log.Fatalf("create file: %v", err)
		}
		if err := setup.ExportPlonkVKSolidity(vk, f, circuit); err != nil {
			f.Close()
			log.Fatalf("export VK: %v", err)
		}
		f.Close()
	}

	fmt.Printf("VK constants written to %s\n", outPath)
}

func exportProofFixture(circuit string) {
	switch circuit {
	case "poi":
		jsonOut, err := poi.ExportProofFixture(".")
		if err != nil {
			log.Fatalf("export proof fixture: %v", err)
		}
		if err := os.WriteFile("proof_fixture.json", jsonOut, 0644); err != nil {
			log.Fatalf("write fixture file: %v", err)
		}
		fmt.Println("\nFixture written to proof_fixture.json")
	case "fsp":
		jsonOut, err := fsp.ExportProofFixture(".")
		if err != nil {
			log.Fatalf("export proof fixture: %v", err)
		}
		if err := os.WriteFile("proof_fixture.json", jsonOut, 0644); err != nil {
			log.Fatalf("write fixture file: %v", err)
		}
		fmt.Println("\nFixture written to proof_fixture.json")
	case "keyleak":
		jsonOut, err := keyleak.ExportProofFixture(".")
		if err != nil {
			log.Fatalf("export proof fixture: %v", err)
		}
		if err := os.WriteFile("proof_fixture.json", jsonOut, 0644); err != nil {
			log.Fatalf("write fixture file: %v", err)
		}
		fmt.Println("\nFixture written to proof_fixture.json")
	default:
		fmt.Fprintf(os.Stderr, "Unknown circuit: %s\n", circuit)
		fmt.Fprintln(os.Stderr, "Available circuits: poi, fsp, keyleak")
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println(`Usage:
  go run ./cmd/export <circuit>         Export proof fixture (JSON)
  go run ./cmd/export <circuit> vk      Export VK constants as Solidity library

Available circuits: poi, fsp, keyleak

Keys must exist in the current directory (run 'go run ./cmd/compile <circuit> dev' first).`)
}

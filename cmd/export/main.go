package main

import (
	"fmt"
	"log"
	"os"

	"github.com/MuriData/muri-zkproof/circuits/poi"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run ./cmd/export <circuit>")
		fmt.Println()
		fmt.Println("Available circuits: poi")
		fmt.Println()
		fmt.Println("Keys must exist in the current directory (run `go run ./cmd/compile <circuit> dev` first).")
		os.Exit(1)
	}

	circuit := os.Args[1]
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
	default:
		fmt.Fprintf(os.Stderr, "Unknown circuit: %s\n", circuit)
		fmt.Fprintln(os.Stderr, "Available circuits: poi")
		os.Exit(1)
	}
}

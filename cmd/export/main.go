package main

import (
	"fmt"
	"log"
	"os"

	"github.com/MuriData/muri-zkproof/circuits/archive_muri"
	"github.com/MuriData/muri-zkproof/circuits/archive_poi"
	"github.com/MuriData/muri-zkproof/circuits/fsp"
	"github.com/MuriData/muri-zkproof/circuits/keyleak"
	"github.com/MuriData/muri-zkproof/circuits/poi"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run ./cmd/export <circuit>")
		fmt.Println()
		fmt.Println("Available circuits: poi, fsp, keyleak, archive_poi, archive_muri")
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
	case "archive_poi":
		jsonOut, err := archive_poi.ExportProofFixture(".")
		if err != nil {
			log.Fatalf("export proof fixture: %v", err)
		}
		if err := os.WriteFile("proof_fixture.json", jsonOut, 0644); err != nil {
			log.Fatalf("write fixture file: %v", err)
		}
		fmt.Println("\nFixture written to proof_fixture.json")
	case "archive_muri":
		jsonOut, err := archive_muri.ExportProofFixture(".")
		if err != nil {
			log.Fatalf("export proof fixture: %v", err)
		}
		if err := os.WriteFile("proof_fixture.json", jsonOut, 0644); err != nil {
			log.Fatalf("write fixture file: %v", err)
		}
		fmt.Println("\nFixture written to proof_fixture.json")
	default:
		fmt.Fprintf(os.Stderr, "Unknown circuit: %s\n", circuit)
		fmt.Fprintln(os.Stderr, "Available circuits: poi, fsp, keyleak, archive_poi, archive_muri")
		os.Exit(1)
	}
}

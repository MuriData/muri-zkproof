package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: go run ./cmd/test <circuit>")
		fmt.Println()
		fmt.Println("Available circuits: poi")
		fmt.Println()
		fmt.Println("Prefer using `go test` directly:")
		fmt.Println("  go test ./circuits/poi/ -v -timeout 5m")
		fmt.Println("  go test ./...                            # all circuits")
		os.Exit(1)
	}

	circuit := os.Args[1]
	fmt.Printf("To run integration tests for the %s circuit, use:\n", circuit)
	fmt.Printf("  go test ./circuits/%s/ -v -timeout 5m\n", circuit)
}

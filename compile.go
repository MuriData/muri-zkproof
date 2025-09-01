package main

import (
	"log"
	"os"

	"github.com/MuriData/muri-zkproof/circuits"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
)

func main() {
	var poiCircuit circuits.PoICircuit
	r1cs, err := frontend.Compile(ecc.BN254.ScalarField(), r1cs.NewBuilder, &poiCircuit)
	if err != nil {
		log.Fatal(err)
	}

	pk, vk, err := groth16.Setup(r1cs)
	if err != nil {
		log.Fatal(err)
	}

	f, err := os.Create("poi_verifier.sol")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	err = vk.ExportSolidity(f)
	if err != nil {
		log.Fatal(err)
	}

	f, err = os.Create("poi_verifier.key")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	_, err = vk.WriteTo(f)
	if err != nil {
		log.Fatal(err)
	}

	f, err = os.Create("poi_prover.key")
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	_, err = pk.WriteTo(f)
	if err != nil {
		log.Fatal(err)
	}
}

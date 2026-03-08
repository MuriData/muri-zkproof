// cmd/wasm/main.go — Browser WASM module for MuriData file operations.
//
// Exposes two functions to JavaScript:
//   - computeFileRoot(fileBytes Uint8Array) → { root: string, numChunks: number }
//   - generateFSPProof(fileBytes Uint8Array, proverKey Uint8Array, verifierKey Uint8Array)
//       → { proof: string[4], root: string, numChunks: number }  (compressed Groth16 proof)
//
// Build: GOOS=js GOARCH=wasm go build -o muri.wasm ./cmd/wasm/

package main

import (
	"bytes"
	"fmt"
	"math/big"
	"syscall/js"

	"github.com/MuriData/muri-zkproof/circuits/fsp"
	"github.com/MuriData/muri-zkproof/pkg/crypto"
	"github.com/MuriData/muri-zkproof/pkg/merkle"
	"github.com/MuriData/muri-zkproof/pkg/setup"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/backend/groth16"
	groth16bn254 "github.com/consensys/gnark/backend/groth16/bn254"
	"github.com/consensys/gnark/frontend"
)

const (
	fileSize     = fsp.FileSize     // 16 KB per chunk
	elementSize  = fsp.ElementSize  // 31 bytes
	numElements  = fsp.NumChunks    // 528 field elements per leaf hash
	maxTreeDepth = fsp.MaxTreeDepth // 20
)

// zeroLeafHash is the Poseidon2 hash for padding leaves, computed once at init.
var zeroLeafHash *big.Int

func init() {
	zeroLeafHash = crypto.ComputeZeroLeafHash(elementSize, numElements)
}

// hashChunk hashes a single 16 KB chunk into a leaf hash.
func hashChunk(chunk []byte) *big.Int {
	return crypto.HashWithDomainTag(crypto.DomainTagReal, chunk, big.NewInt(1), elementSize, numElements)
}

// buildSMT splits file bytes into chunks and builds the sparse Merkle tree.
func buildSMT(fileBytes []byte) *merkle.SparseMerkleTree {
	chunks := merkle.SplitIntoChunks(fileBytes, fileSize)
	return merkle.GenerateSparseMerkleTree(chunks, maxTreeDepth, hashChunk, zeroLeafHash)
}

// jsUint8ArrayToBytes copies a JS Uint8Array into a Go []byte.
func jsUint8ArrayToBytes(val js.Value) []byte {
	length := val.Get("length").Int()
	buf := make([]byte, length)
	js.CopyBytesToGo(buf, val)
	return buf
}

// computeFileRootJS is the JS-callable wrapper for computing a file's Merkle root.
//
//	const result = await computeFileRoot(fileUint8Array);
//	console.log(result.root, result.numChunks);
func computeFileRootJS(_ js.Value, args []js.Value) any {
	handler := js.FuncOf(func(_ js.Value, promiseArgs []js.Value) any {
		resolve := promiseArgs[0]
		reject := promiseArgs[1]

		go func() {
			defer func() {
				if r := recover(); r != nil {
					reject.Invoke(fmt.Sprintf("panic: %v", r))
				}
			}()

			if len(args) < 1 {
				reject.Invoke("computeFileRoot: expected 1 argument (Uint8Array)")
				return
			}

			fileBytes := jsUint8ArrayToBytes(args[0])
			smt := buildSMT(fileBytes)

			result := js.Global().Get("Object").New()
			result.Set("root", fmt.Sprintf("%s", smt.Root.Text(10)))
			result.Set("numChunks", smt.NumLeaves)
			resolve.Invoke(result)
		}()

		return nil
	})

	return js.Global().Get("Promise").New(handler)
}

// generateFSPProofJS is the JS-callable wrapper for generating an FSP Groth16 proof.
//
//	const result = await generateFSPProof(fileUint8Array, proverKeyBytes, verifierKeyBytes);
//	console.log(result.proof, result.root, result.numChunks);
func generateFSPProofJS(_ js.Value, args []js.Value) any {
	handler := js.FuncOf(func(_ js.Value, promiseArgs []js.Value) any {
		resolve := promiseArgs[0]
		reject := promiseArgs[1]

		go func() {
			defer func() {
				if r := recover(); r != nil {
					reject.Invoke(fmt.Sprintf("panic: %v", r))
				}
			}()

			if len(args) < 3 {
				reject.Invoke("generateFSPProof: expected 3 arguments (fileBytes, proverKey, verifierKey)")
				return
			}

			fileBytes := jsUint8ArrayToBytes(args[0])
			pkBytes := jsUint8ArrayToBytes(args[1])
			vkBytes := jsUint8ArrayToBytes(args[2])

			// 1. Compile circuit
			ccs, err := setup.CompileCircuit(&fsp.FSPCircuit{})
			if err != nil {
				reject.Invoke(fmt.Sprintf("compile circuit: %v", err))
				return
			}

			// 2. Deserialize proving key
			pk := groth16.NewProvingKey(ecc.BN254)
			if _, err := pk.ReadFrom(bytes.NewReader(pkBytes)); err != nil {
				reject.Invoke(fmt.Sprintf("read proving key: %v", err))
				return
			}

			// 3. Deserialize verifying key
			vk := groth16.NewVerifyingKey(ecc.BN254)
			if _, err := vk.ReadFrom(bytes.NewReader(vkBytes)); err != nil {
				reject.Invoke(fmt.Sprintf("read verifying key: %v", err))
				return
			}

			// 4. Build SMT + prepare witness
			smt := buildSMT(fileBytes)

			witnessResult, err := fsp.PrepareWitness(smt)
			if err != nil {
				reject.Invoke(fmt.Sprintf("prepare witness: %v", err))
				return
			}

			// 5. Create gnark witness
			witness, err := frontend.NewWitness(&witnessResult.Assignment, ecc.BN254.ScalarField())
			if err != nil {
				reject.Invoke(fmt.Sprintf("create witness: %v", err))
				return
			}

			// 6. Prove
			proof, err := groth16.Prove(ccs, pk, witness)
			if err != nil {
				reject.Invoke(fmt.Sprintf("prove: %v", err))
				return
			}

			// 7. Verify locally
			publicWitness, err := witness.Public()
			if err != nil {
				reject.Invoke(fmt.Sprintf("extract public witness: %v", err))
				return
			}
			if err := groth16.Verify(proof, vk, publicWitness); err != nil {
				reject.Invoke(fmt.Sprintf("proof verification failed: %v", err))
				return
			}

			// 8. Extract uncompressed proof points, then compress to [4]uint256
			bn254Proof := proof.(*groth16bn254.Proof)

			aX := new(big.Int)
			aY := new(big.Int)
			bn254Proof.Ar.X.BigInt(aX)
			bn254Proof.Ar.Y.BigInt(aY)

			bX0 := new(big.Int)
			bX1 := new(big.Int)
			bY0 := new(big.Int)
			bY1 := new(big.Int)
			bn254Proof.Bs.X.A0.BigInt(bX0)
			bn254Proof.Bs.X.A1.BigInt(bX1)
			bn254Proof.Bs.Y.A0.BigInt(bY0)
			bn254Proof.Bs.Y.A1.BigInt(bY1)

			cX := new(big.Int)
			cY := new(big.Int)
			bn254Proof.Krs.X.BigInt(cX)
			bn254Proof.Krs.Y.BigInt(cY)

			uncompressed := [8]*big.Int{aX, aY, bX1, bX0, bY1, bY0, cX, cY}
			compressedProof, err := crypto.CompressProof(uncompressed)
			if err != nil {
				reject.Invoke(fmt.Sprintf("compress proof: %v", err))
				return
			}

			// Build JS result
			result := js.Global().Get("Object").New()
			result.Set("root", smt.Root.Text(10))
			result.Set("numChunks", smt.NumLeaves)

			proofArray := js.Global().Get("Array").New(4)
			for i := 0; i < 4; i++ {
				proofArray.SetIndex(i, compressedProof[i].Text(10))
			}
			result.Set("proof", proofArray)

			resolve.Invoke(result)
		}()

		return nil
	})

	return js.Global().Get("Promise").New(handler)
}

func main() {
	js.Global().Set("muriComputeFileRoot", js.FuncOf(computeFileRootJS))
	js.Global().Set("muriGenerateFSPProof", js.FuncOf(generateFSPProofJS))

	// Keep the Go runtime alive.
	select {}
}

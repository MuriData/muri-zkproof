// cmd/wasm/main.go — Browser WASM module for MuriData file operations.
//
// Exposes to JavaScript:
//   - muriComputeFileRoot(fileBytes)                          → { root, numChunks }
//   - muriGenerateFSPProof(fileBytes, pk, vk [, onProgress]) → { proof, root, numChunks }
//   - muriHashChunks(filePortionBytes)                        → Uint8Array (32-byte leaf hashes)
//   - muriComputeRootFromHashes(hashes, numLeaves)            → { root, numChunks }
//   - muriGenerateFSPProofFromHashes(hashes, numLeaves, pk, vk [, onProgress])
//         → { proof, root, numChunks }
//
// The *FromHashes variants accept pre-computed leaf hashes (produced by
// muriHashChunks in parallel workers) so leaf hashing can be parallelized
// across multiple Web Workers while proof generation runs in one.
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
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
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

// deserializeLeafHashes converts concatenated 32-byte big-endian field element
// bytes into a slice of *big.Int leaf hashes.
func deserializeLeafHashes(data []byte) []*big.Int {
	n := len(data) / 32
	hashes := make([]*big.Int, n)
	for i := 0; i < n; i++ {
		var elem fr.Element
		elem.SetBytes(data[i*32 : (i+1)*32])
		hashes[i] = new(big.Int)
		elem.BigInt(hashes[i])
	}
	return hashes
}

// makeProgressReporter builds a closure that calls a JS progress callback.
// Returns a no-op if the callback is missing/undefined.
func makeProgressReporter(args []js.Value, idx int) func(string, map[string]any) {
	if len(args) <= idx || args[idx].Type() != js.TypeFunction {
		return func(string, map[string]any) {}
	}
	cb := args[idx]
	return func(stage string, extra map[string]any) {
		obj := js.Global().Get("Object").New()
		obj.Set("stage", stage)
		for k, v := range extra {
			obj.Set(k, v)
		}
		cb.Invoke(obj)
	}
}

// fspProveAndCompress compiles the FSP circuit, deserializes keys, runs
// Groth16 prove+verify, and returns the compressed proof + SMT root as a JS
// result object.
func fspProveAndCompress(smt *merkle.SparseMerkleTree, pkBytes, vkBytes []byte) (js.Value, error) {
	ccs, err := setup.CompileCircuit(&fsp.FSPCircuit{})
	if err != nil {
		return js.Undefined(), fmt.Errorf("compile circuit: %w", err)
	}

	pk := groth16.NewProvingKey(ecc.BN254)
	if _, err := pk.ReadFrom(bytes.NewReader(pkBytes)); err != nil {
		return js.Undefined(), fmt.Errorf("read proving key: %w", err)
	}

	vk := groth16.NewVerifyingKey(ecc.BN254)
	if _, err := vk.ReadFrom(bytes.NewReader(vkBytes)); err != nil {
		return js.Undefined(), fmt.Errorf("read verifying key: %w", err)
	}

	witnessResult, err := fsp.PrepareWitness(smt)
	if err != nil {
		return js.Undefined(), fmt.Errorf("prepare witness: %w", err)
	}

	witness, err := frontend.NewWitness(&witnessResult.Assignment, ecc.BN254.ScalarField())
	if err != nil {
		return js.Undefined(), fmt.Errorf("create witness: %w", err)
	}

	proof, err := groth16.Prove(ccs, pk, witness)
	if err != nil {
		return js.Undefined(), fmt.Errorf("prove: %w", err)
	}

	publicWitness, err := witness.Public()
	if err != nil {
		return js.Undefined(), fmt.Errorf("extract public witness: %w", err)
	}
	if err := groth16.Verify(proof, vk, publicWitness); err != nil {
		return js.Undefined(), fmt.Errorf("proof verification failed: %w", err)
	}

	// Extract and compress proof points.
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
		return js.Undefined(), fmt.Errorf("compress proof: %w", err)
	}

	// Build JS result.
	result := js.Global().Get("Object").New()
	result.Set("root", smt.Root.Text(10))
	result.Set("numChunks", smt.NumLeaves)

	proofArray := js.Global().Get("Array").New(4)
	for i := 0; i < 4; i++ {
		proofArray.SetIndex(i, compressedProof[i].Text(10))
	}
	result.Set("proof", proofArray)

	return result, nil
}

// ---------------------------------------------------------------------------
// JS-exposed functions
// ---------------------------------------------------------------------------

// computeFileRootJS: muriComputeFileRoot(fileBytes) → { root, numChunks }
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
			result.Set("root", smt.Root.Text(10))
			result.Set("numChunks", smt.NumLeaves)
			resolve.Invoke(result)
		}()

		return nil
	})

	return js.Global().Get("Promise").New(handler)
}

// generateFSPProofJS: muriGenerateFSPProof(fileBytes, pk, vk [, onProgress])
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

			reportProgress := makeProgressReporter(args, 3)

			fileBytes := jsUint8ArrayToBytes(args[0])
			pkBytes := jsUint8ArrayToBytes(args[1])
			vkBytes := jsUint8ArrayToBytes(args[2])

			smt := buildSMT(fileBytes)

			reportProgress("root", map[string]any{
				"root":      smt.Root.Text(10),
				"numChunks": smt.NumLeaves,
			})

			result, err := fspProveAndCompress(smt, pkBytes, vkBytes)
			if err != nil {
				reject.Invoke(err.Error())
				return
			}
			resolve.Invoke(result)
		}()

		return nil
	})

	return js.Global().Get("Promise").New(handler)
}

// hashChunksJS: muriHashChunks(filePortionBytes) → Uint8Array
//
// Splits the input into 16 KB chunks, hashes each with Poseidon2, and returns
// concatenated 32-byte big-endian leaf hashes. Designed to be called from
// multiple Web Workers in parallel, each processing a portion of the file.
func hashChunksJS(_ js.Value, args []js.Value) any {
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
				reject.Invoke("muriHashChunks: expected 1 argument (Uint8Array)")
				return
			}

			fileBytes := jsUint8ArrayToBytes(args[0])
			chunks := merkle.SplitIntoChunks(fileBytes, fileSize)

			buf := make([]byte, len(chunks)*32)
			for i, chunk := range chunks {
				h := hashChunk(chunk)
				var elem fr.Element
				elem.SetBigInt(h)
				b := elem.Bytes()
				copy(buf[i*32:(i+1)*32], b[:])
			}

			jsResult := js.Global().Get("Uint8Array").New(len(buf))
			js.CopyBytesToJS(jsResult, buf)
			resolve.Invoke(jsResult)
		}()

		return nil
	})

	return js.Global().Get("Promise").New(handler)
}

// computeRootFromHashesJS: muriComputeRootFromHashes(hashes, numLeaves) → { root, numChunks }
func computeRootFromHashesJS(_ js.Value, args []js.Value) any {
	handler := js.FuncOf(func(_ js.Value, promiseArgs []js.Value) any {
		resolve := promiseArgs[0]
		reject := promiseArgs[1]

		go func() {
			defer func() {
				if r := recover(); r != nil {
					reject.Invoke(fmt.Sprintf("panic: %v", r))
				}
			}()

			if len(args) < 2 {
				reject.Invoke("muriComputeRootFromHashes: expected 2 args (Uint8Array, numLeaves)")
				return
			}

			hashBytes := jsUint8ArrayToBytes(args[0])
			numLeaves := args[1].Int()
			leafHashes := deserializeLeafHashes(hashBytes)

			smt := merkle.BuildSMTFromLeafHashes(leafHashes, maxTreeDepth, zeroLeafHash)

			result := js.Global().Get("Object").New()
			result.Set("root", smt.Root.Text(10))
			result.Set("numChunks", numLeaves)
			resolve.Invoke(result)
		}()

		return nil
	})

	return js.Global().Get("Promise").New(handler)
}

// generateFSPProofFromHashesJS: muriGenerateFSPProofFromHashes(hashes, numLeaves, pk, vk [, onProgress])
func generateFSPProofFromHashesJS(_ js.Value, args []js.Value) any {
	handler := js.FuncOf(func(_ js.Value, promiseArgs []js.Value) any {
		resolve := promiseArgs[0]
		reject := promiseArgs[1]

		go func() {
			defer func() {
				if r := recover(); r != nil {
					reject.Invoke(fmt.Sprintf("panic: %v", r))
				}
			}()

			if len(args) < 4 {
				reject.Invoke("muriGenerateFSPProofFromHashes: expected 4+ args (hashes, numLeaves, pk, vk [, onProgress])")
				return
			}

			reportProgress := makeProgressReporter(args, 4)

			hashBytes := jsUint8ArrayToBytes(args[0])
			numLeaves := args[1].Int()
			pkBytes := jsUint8ArrayToBytes(args[2])
			vkBytes := jsUint8ArrayToBytes(args[3])

			leafHashes := deserializeLeafHashes(hashBytes)
			_ = numLeaves // numLeaves used for the result; tree uses len(leafHashes)

			smt := merkle.BuildSMTFromLeafHashes(leafHashes, maxTreeDepth, zeroLeafHash)

			reportProgress("root", map[string]any{
				"root":      smt.Root.Text(10),
				"numChunks": smt.NumLeaves,
			})

			result, err := fspProveAndCompress(smt, pkBytes, vkBytes)
			if err != nil {
				reject.Invoke(err.Error())
				return
			}
			resolve.Invoke(result)
		}()

		return nil
	})

	return js.Global().Get("Promise").New(handler)
}

func main() {
	js.Global().Set("muriComputeFileRoot", js.FuncOf(computeFileRootJS))
	js.Global().Set("muriGenerateFSPProof", js.FuncOf(generateFSPProofJS))
	js.Global().Set("muriHashChunks", js.FuncOf(hashChunksJS))
	js.Global().Set("muriComputeRootFromHashes", js.FuncOf(computeRootFromHashesJS))
	js.Global().Set("muriGenerateFSPProofFromHashes", js.FuncOf(generateFSPProofFromHashesJS))

	// Keep the Go runtime alive.
	select {}
}

# muri-zkproof

Zero-knowledge proof circuits and tooling that power MuriData's decentralized storage verification. This repository builds the Groth16 artifacts consumed by the on-chain verifier in [muri-contracts](https://github.com/MuriData/muri-contracts) and provides utilities for generating proofs over data commitments.

## Overview
- Multi-circuit architecture — each circuit lives in its own package under `circuits/` with shared infrastructure in `pkg/`.
- Groth16 circuits (BN254) written with [`gnark`](https://github.com/ConsenSys/gnark).
- MPC ceremony support for production trusted setup (Powers of Tau + circuit-specific phases).
- CLI tools to compile any registered circuit, produce proving/verifying keys, and export Solidity verifier contracts.

### Available circuits

| Circuit | Package | Description |
|---------|---------|-------------|
| **PoI** (Proof of Integrity) | `circuits/poi` | Proves a Poseidon2 commitment matches a Merkle tree leaf selected deterministically from public randomness, with hash-based key ownership |

## How it works (PoI circuit)
1. **Chunking and hashing** – A prover splits user data into fixed 16 KiB blobs, then converts the target blob into field elements. Inside the circuit each element is multiplied by the public randomness and hashed with Poseidon2 to form a binding message: `msg = H(Bytes × Randomness)`.
2. **Key ownership** – The prover's public key is derived as `publicKey = H(secretKey)` using Poseidon2. The circuit re-derives this hash and asserts equality with the public input, proving the prover knows the secret key registered on-chain.
3. **VRF commitment** – The circuit computes `commitment = H(secretKey, msg, randomness, publicKey)`. This is deterministic and uniquely bound to the secret key — a prover cannot bias the output without using a different key, which would fail the key ownership check.
4. **Deterministic leaf choice** – The public randomness is decomposed into bits; the circuit derives the leaf index from those bits so both prover and verifier agree on the unique Merkle leaf that must be proven. This prevents selective disclosure.
5. **Merkle membership** – Using the supplied Merkle path and direction bits, the circuit replays the Poseidon2 hash chain and enforces that the selected leaf links back to the public Merkle root. The circuit enforces minimum proof depth of 1 (at least 2 leaves) and contiguous proof encoding (no active levels after padding).
6. **Groth16 proof generation** – With the full witness (private bytes, secret key, Merkle path) the prover produces a Groth16 proof using `poi_prover.key`. On-chain, `poi_verifier.sol` checks the proof against the four public inputs `[commitment, randomness, publicKey, rootHash]`.

The end result is a statement of the form: "Given this commitment, randomness, Merkle root, and public key hash, I know the secret key behind that public key and can reveal a unique chunk inside the Merkle tree that hashes to the commitment," without exposing the chunk contents or secret key on-chain.

## Public inputs (4 field elements)

| Index | Name | Description |
|-------|------|-------------|
| 0 | `commitment` | VRF output: `H(secretKey, msg, randomness, publicKey)` |
| 1 | `randomness` | Challenge randomness (determines leaf selection) |
| 2 | `publicKey` | `H(secretKey)` — registered on-chain during node staking |
| 3 | `rootHash` | Merkle root of the file's chunk tree |

## Relationship to `muri-contracts`
The Solidity verifier exported from this project (`poi_verifier.sol`) is linked into `muri-contracts` via the `muri-artifacts` git submodule. When you regenerate the verifier or keys:
1. Run `go run ./cmd/compile poi dev` in this repository to rebuild the Groth16 setup (dev only; use the MPC ceremony for production).
2. Copy `poi_verifier.sol`, `poi_prover.key`, and `poi_verifier.key` into `muri-artifacts/poi/` and commit (keys are Git LFS tracked).
3. Update the submodule pin: `cd muri-contracts && git submodule update --remote lib/muri-artifacts`.
4. Run `go run ./cmd/export poi` to regenerate `proof_fixture.json` for Solidity tests.
5. Rebuild contracts: `forge build`.

## Repository layout
```
muri-zkproof/
├── circuits/
│   └── poi/                 # PoI (Proof of Integrity) circuit
│       ├── circuit.go       # PoICircuit struct + Define()
│       ├── merkle.go        # MerkleProofCircuit (sub-circuit)
│       ├── config.go        # PoI-specific constants (FileSize, MaxTreeDepth, etc.)
│       ├── witness.go       # PrepareWitness, WitnessResult, HashChunk
│       ├── export.go        # ExportProofFixture() — deterministic fixture generation
│       └── poi_test.go      # Integration tests
├── pkg/
│   ├── crypto/              # Poseidon2 hashing, key derivation, commitment
│   ├── field/               # Field element ↔ byte conversions
│   ├── merkle/              # Merkle tree construction and proof verification
│   └── setup/               # Groth16 compile, setup, key export, MPC ceremony
├── cmd/
│   ├── compile/             # CLI: go run ./cmd/compile <circuit> dev|ceremony ...
│   ├── export/              # CLI: go run ./cmd/export <circuit>
│   └── test/                # CLI: go run ./cmd/test <circuit>
└── go.mod
```

**Adding a new circuit:** Create a new package under `circuits/` with its own `config.go`, `circuit.go`, `witness.go`, etc. Register it in the circuit registry in `cmd/compile/main.go` and `cmd/export/main.go`.

## Getting started
### Prerequisites
- Go 1.24+
- git

### Install dependencies
```bash
go mod download
```

### Run integration tests
```bash
go test ./circuits/poi/ -v -timeout 5m    # PoI circuit end-to-end
go test ./...                              # all circuits
```
The PoI test will:
1. Compile the circuit and perform a single-party Groth16 setup.
2. Generate random data (128 KB, 8 chunks) and build a Poseidon2 Merkle tree.
3. Pick a leaf deterministically from random challenge randomness.
4. Generate a secret key, derive the public key and VRF commitment.
5. Build the full circuit witness, generate a Groth16 proof, and verify it.

### Generate deterministic proof fixtures
```bash
go run ./cmd/export poi
```
Outputs `proof_fixture.json` with Solidity-formatted proof points and public inputs for contract tests.

## Generating fresh setup artifacts

### Dev mode (single-party, insecure)
```bash
go run ./cmd/compile poi dev
```

### MPC ceremony (production)
```bash
go run ./cmd/compile poi ceremony p1-init            # Initialize Phase 1 (Powers of Tau)
go run ./cmd/compile poi ceremony p1-contribute      # Add a Phase 1 contribution (repeat N times)
go run ./cmd/compile poi ceremony p1-verify HEX      # Verify Phase 1 & seal with random beacon

go run ./cmd/compile poi ceremony p2-init            # Initialize Phase 2 (circuit-specific)
go run ./cmd/compile poi ceremony p2-contribute      # Add a Phase 2 contribution (repeat M times)
go run ./cmd/compile poi ceremony p2-verify HEX      # Verify Phase 2, seal & export keys
```
Security: 1-of-N honest — if any single contributor is honest, the setup is secure. Use a public randomness source (e.g. League of Entropy) for the beacon, evaluated after the last contribution.

Both modes write:
- `poi_prover.key` – proving key (keep private, distribute only to proving infrastructure).
- `poi_verifier.key` – verifying key (public, required by off-chain verifiers).
- `poi_verifier.sol` – Solidity verifier contract to be imported into `muri-contracts`.

## Integrating into a prover service
1. **Build chunks and Merkle tree** – Use `merkle.SplitIntoChunks(data, poi.FileSize)` and `merkle.GenerateMerkleTree(chunks, poi.FileSize, poi.HashChunk)`.
2. **Prepare witness** – Call `poi.PrepareWitness(secretKey, randomness, chunks, merkleTree)`. This derives the chunk index, Merkle proof, public key, message hash, and commitment in one call.
3. **Produce a proof** – Call `groth16.Prove` with the proving key and the witness from `PrepareWitness`. The output proof and public inputs can be relayed on-chain.

## Configuration knobs (PoI)
Defined in `circuits/poi/config.go`:
- `FileSize` (16 KiB) – segment size used when chunking input files.
- `ElementSize` (31 bytes) – byte length for each field element inside the circuit.
- `NumChunks` (528) – derived maximum number of field elements per chunk.
- `MaxTreeDepth` (20) – maximum Merkle proof depth enforced in the circuit.

Adjust these values only when you intend to regenerate the trusted setup and update the verifier contracts, as they alter the circuit constraints.

## License
Apache 2.0 – see `LICENSE`.

# muri-zkproof

Zero-knowledge proof circuits and tooling that power MuriData's proof-of-integrity (PoI) workflow. This repository builds the Groth16 artifacts consumed by the on-chain verifier in [muri-contracts](https://github.com/MuriData/muri-contracts) and provides utilities for generating proofs over data commitments.

## Overview
- Groth16 circuit (BN254) written with [`gnark`](https://github.com/ConsenSys/gnark) that proves a Poseidon2 commitment matches a Merkle tree leaf selected deterministically from public randomness.
- Hash-based VRF for key ownership and commitment derivation — no elliptic curve operations in the circuit.
- Deterministic leaf selection ensures that a prover cannot cherry-pick leaves; selection logic is enforced inside the circuit.
- Merkle membership proof verification with Poseidon2 hashing and bounded tree depth (minimum depth 1), configurable via `config/constants.go`.
- MPC ceremony support for production trusted setup (Powers of Tau + circuit-specific phases).
- CLI helpers to compile the circuit, produce proving/verifying keys, and export a Solidity verifier contract compatible with Muri's infrastructure.

## How it works
1. **Chunking and hashing** – A prover splits user data into fixed 16 KiB blobs, then converts the target blob into field elements (`utils.Bytes2Field`). Inside the circuit each element is multiplied by the public randomness and hashed with Poseidon2 to form a binding message: `msg = H(Bytes × Randomness)`.
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
1. Run `go run compile.go` in this repository to rebuild the Groth16 setup.
2. Copy `poi_verifier.sol`, `poi_prover.key`, and `poi_verifier.key` into `muri-artifacts/` and commit (keys are Git LFS tracked).
3. Update the submodule pin: `cd muri-contracts && git submodule update --remote lib/muri-artifacts`.
4. Run `go run export_proof.go` to regenerate `proof_fixture.json` for Solidity tests.
5. Rebuild contracts: `forge build`.

## Repository layout
- `circuits/` – gnark circuits for the PoI proof (`poi.go`) and the reusable Merkle proof subcircuit (`merkle.go`).
- `config/` – global circuit parameters (chunk sizing, Merkle depth).
- `utils/` – reusable Go helpers for Poseidon2 hashing, key derivation, chunking files, Merkle tree construction, and witness preparation.
- `compile.go` – Groth16 setup tool. Dev mode (single-party) and MPC ceremony mode (multi-party trusted setup).
- `test.go` – end-to-end flow: random data → chunk → Merkle tree → generate & verify proof.
- `export_proof.go` – generates deterministic proof fixtures for Solidity tests.
- `poi_prover.key`, `poi_verifier.key`, `poi_verifier.sol` – pre-generated setup artifacts (replace with your own for production via MPC ceremony).

## Getting started
### Prerequisites
- Go 1.24+
- git

### Install dependencies
```bash
go mod download
```

### Run the demo flow
```bash
go run test.go
```
The program will:
1. Generate random data (128 KB, 8 chunks) and build a Poseidon2 Merkle tree.
2. Pick a leaf deterministically from random challenge randomness.
3. Generate a secret key, derive the public key and VRF commitment.
4. Build the full circuit witness via `utils.PrepareWitness`.
5. Generate a Groth16 proof and verify it using the bundled verifying key.

### Generate deterministic proof fixtures
```bash
go run export_proof.go
```
Outputs `proof_fixture.json` with Solidity-formatted proof points and public inputs for contract tests.

## Generating fresh setup artifacts

### Dev mode (single-party, insecure)
```bash
go run compile.go
```

### MPC ceremony (production)
```bash
go run compile.go ceremony p1-init            # Initialize Phase 1 (Powers of Tau)
go run compile.go ceremony p1-contribute      # Add a Phase 1 contribution (repeat N times)
go run compile.go ceremony p1-verify HEX      # Verify Phase 1 & seal with random beacon

go run compile.go ceremony p2-init            # Initialize Phase 2 (circuit-specific)
go run compile.go ceremony p2-contribute      # Add a Phase 2 contribution (repeat M times)
go run compile.go ceremony p2-verify HEX      # Verify Phase 2, seal & export keys
```
Security: 1-of-N honest — if any single contributor is honest, the setup is secure. Use a public randomness source (e.g. League of Entropy) for the beacon, evaluated after the last contribution.

Both modes write:
- `poi_prover.key` – proving key (keep private, distribute only to proving infrastructure).
- `poi_verifier.key` – verifying key (public, required by off-chain verifiers).
- `poi_verifier.sol` – Solidity verifier contract to be imported into `muri-contracts`.

## Integrating into a prover service
1. **Build chunks and Merkle tree** – Use `utils.SplitIntoChunks` and `utils.GenerateMerkleTree`.
2. **Prepare witness** – Call `utils.PrepareWitness(secretKey, randomness, chunks, merkleTree)`. This derives the chunk index, Merkle proof, public key, message hash, and commitment in one call.
3. **Produce a proof** – Call `groth16.Prove` with the proving key and the witness from `PrepareWitness`. The output proof and public inputs can be relayed on-chain.

## Configuration knobs
Defined in `config/constants.go`:
- `FileSize` (16 KiB) – segment size used when chunking input files.
- `ElementSize` (31 bytes) – byte length for each field element inside the circuit.
- `NumChunks` (528) – derived maximum number of field elements per chunk.
- `MaxTreeDepth` (20) – maximum Merkle proof depth enforced in the circuit.

Adjust these values only when you intend to regenerate the trusted setup and update the verifier contracts, as they alter the circuit constraints.

## License
Apache 2.0 – see `LICENSE`.

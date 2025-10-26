# muri-zkproof

Zero-knowledge proof circuits and tooling that power MuriData’s proof-of-inclusion (PoI) workflow. This repository builds the Groth16 artifacts consumed by the on-chain verifier in [muri-contracts](https://github.com/MuriData/muri-contracts) and provides utilities for generating proofs over data commitments.

## Overview
- Groth16 circuit (BN254) written with [`gnark`](https://github.com/ConsenSys/gnark) that proves a MiMC commitment matches a Merkle tree leaf selected deterministically from public randomness.
- Deterministic leaf selection ensures that a prover cannot cherry-pick leaves; selection logic is enforced inside the circuit.
- Merkle membership proof verification with MiMC hashing and bounded tree depth, configurable via `config/constants.go`.
- CLI helpers to compile the circuit, produce proving/verifying keys, and export a Solidity verifier contract compatible with Muri’s infrastructure.

## How it works
1. **Chunking and hashing** – A prover splits user data into fixed 16 KiB blobs, then converts the target blob into field elements (`utils.Bytes2Field`). Inside the circuit each element is multiplied by the public randomness and hashed with MiMC to form a binding commitment.
2. **Signer attestation** – The prover signs the MiMC commitment using an EDDSA key pair (twisted Edwards over BN254). The circuit verifies the signature against the public key that is provided as a public input.
3. **Deterministic leaf choice** – The public randomness is decomposed into bits; the circuit derives the leaf index from those bits so both prover and verifier agree on the unique Merkle leaf that must be proven. This prevents selective disclosure.
4. **Merkle membership** – Using the supplied Merkle path and direction bits, the circuit replays the MiMC hash chain and enforces that the selected leaf links back to the public Merkle root. Proof paths are padded and range-checked so unused levels cannot contradict the commitment.
5. **Groth16 proof generation** – With the full witness (private bytes, signature, Merkle path) the prover produces a Groth16 proof using `poi_prover.key`. On-chain, `poi_verifier.sol` checks the proof using the public inputs `(commitment, randomness, Merkle root, EDDSA public key)` to confirm the statement.

The end result is a statement of the form: “Given this commitment, randomness, Merkle root, and publisher key, I can reveal a unique chunk inside the Merkle tree that hashes to the commitment and is endorsed by the publisher,” without exposing the chunk contents on-chain.

## Relationship to `muri-contracts`
The Solidity verifier exported from this project (`poi_verifier.sol`) is linked directly inside the `muri-contracts` repository. When you regenerate the verifier or keys:
1. Run `go run compile.go` in this repository to rebuild the Groth16 setup.
2. Copy the fresh `poi_verifier.sol` (and, if required, the binary `poi_verifier.key`) into the appropriate location inside `muri-contracts`.
3. Recompile and deploy the smart contracts so they reference the new verifying key.

Regenerating the proving key (`poi_prover.key`) is required for any prover service that produces on-chain proofs. Keep the proving key private and distribute it securely to the proving infrastructure only.

## Repository layout
- `circuits/` – gnark circuits for the PoI proof and the reusable Merkle proof subcircuit.
- `config/` – global circuit parameters (chunk sizing, Merkle depth).
- `utils/` – reusable Go helpers for hashing, EDDSA signatures, chunking files, and Merkle tree construction.
- `compile.go` – command-line tool that performs Groth16 setup and exports Solidity + key artifacts.
- `test.go` – example end-to-end flow: chunk a file, generate a proof, and verify it.
- `poi_prover.key`, `poi_verifier.key`, `poi_verifier.sol` – pre-generated setup artifacts for convenience (replace with your own for production).

## Getting started
### Prerequisites
- Go 1.22+ (tested with Go 1.24.x)
- git

### Install dependencies
```bash
go mod download
```

### Run the demo flow
The sample `test.go` program walks through the entire workflow against `92986402.jpeg` (bundled for convenience):
```bash
go run test.go
```
The program will:
1. Split the input into fixed-size chunks and build a MiMC-based Merkle tree.
2. Pick a leaf deterministically from public randomness.
3. Commit to the selected chunk, sign the commitment, and build a PoI witness.
4. Generate a Groth16 proof and verify it using the bundled verifying key.

Customize the demo by replacing `92986402.jpeg` or editing `test.go` to read a different file or randomness source.

## Generating fresh setup artifacts
Run:
```bash
go run compile.go
```
This performs Groth16 setup for the PoI circuit and writes:
- `poi_prover.key` – proving key (keep private).
- `poi_verifier.key` – verifying key (public, required by off-chain verifiers).
- `poi_verifier.sol` – Solidity verifier contract to be imported into `muri-contracts`.

Whenever you regenerate the setup, update both your prover infrastructure and the deployed Solidity verifier so they use the same verifying key.

## Integrating into a prover service
1. **Commit to user data** – Use `utils.Hash` to hash the raw chunk with randomness, and persist the MiMC commitment together with the randomness you will reveal.
2. **Generate Merkle inclusion data** – Build a Merkle tree with `utils.GenerateMerkleTree`, or integrate these helpers into your pipeline so you can obtain the sibling path and direction bits for each inclusion.
3. **Construct a witness** – Populate `circuits.PoICircuit` with the private bytes, signature, Merkle path, and public inputs (commitment, randomness, root hash, EDDSA public key).
4. **Produce a proof** – Call `groth16.Prove` with the proving key (`poi_prover.key`). The output proof and public inputs can be relayed on-chain to the verifier in `muri-contracts`.

## Configuration knobs
Defined in `config/constants.go`:
- `FileSize` – segment size used when chunking input files (defaults to 16 KiB).
- `ElementSize` – byte length for each field element inside the circuit.
- `NumChunks` – derived maximum number of chunks supported by the commitment portion of the circuit.
- `MaxTreeDepth` – maximum Merkle proof depth enforced in the circuit.

Adjust these values only when you intend to regenerate the trusted setup and update the verifier contracts, as they alter the circuit constraints.

## License
Apache 2.0 – see `LICENSE`.

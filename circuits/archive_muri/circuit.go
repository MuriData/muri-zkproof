package archive_muri

import (
	"math/big"

	"github.com/MuriData/muri-zkproof/circuits/shared"
	"github.com/MuriData/muri-zkproof/pkg/archive"
	"github.com/MuriData/muri-zkproof/pkg/crypto"
	"github.com/MuriData/muri-zkproof/pkg/merkle"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/permutation/poseidon2"
)

var zeroLeafHash *big.Int

func init() {
	zeroLeafHash = crypto.ComputeZeroLeafHash(ElementSize, NumFieldElements)
	_ = merkle.PrecomputeZeroHashes(ArchiveTreeDepth, zeroLeafHash)
}

// newHasher creates a Poseidon2 Merkle-Damgard hasher from the API.
func newHasher(api frontend.API) hash.FieldHasher {
	p, _ := poseidon2.NewPoseidon2FromParameters(api, 2, 6, 50)
	return hash.NewMerkleDamgardHasher(api, p, 0)
}

// SlotMappingWitness provides slot metadata for logical-to-physical mapping.
type SlotMappingWitness struct {
	SlotIndex        frontend.Variable    `gnark:"slotIndex"`
	FileRoot         frontend.Variable    `gnark:"fileRoot"`
	NumChunks        frontend.Variable    `gnark:"numChunks"`
	CumulativeChunks frontend.Variable    `gnark:"cumulativeChunks"`
	SlotProof        shared.MerkleProof10 `gnark:"slotProof"`
}

// ChunkOpening holds the witness for opening a chunk against both trees.
type ChunkOpening struct {
	OrigElements [NumFieldElements]frontend.Variable `gnark:"origElements"`
	Enc2Elements [NumFieldElements]frontend.Variable `gnark:"enc2Elements"`
	OrigProof    shared.MerkleProof20                `gnark:"origProof"`
	ReplicaProof shared.MerkleProof30                `gnark:"replicaProof"`
	SlotMapping  SlotMappingWitness                  `gnark:"slotMapping"`
}

// Pass2ReversalWitness provides enc2 dependencies to derive one enc1 value.
// IsLastElem is 1 when the position is N-1 (uses seed key), 0 otherwise.
type Pass2ReversalWitness struct {
	IsLastElem frontend.Variable    `gnark:"isLastElem"`
	Enc2Next   frontend.Variable    `gnark:"enc2Next"`
	Enc2BPs    [K]frontend.Variable `gnark:"enc2BPs"`
}

// HopWitness holds witness data for a single hop (MURI.md Section 7.1).
// ElemIdx is the flat element index j in [0, N).
// OrigVal is orig[j] — Merkle-verified at origin/terminus, witnessed at intermediate hops.
type HopWitness struct {
	ElemIdx       frontend.Variable            `gnark:"elemIdx"`
	Enc2Val       frontend.Variable            `gnark:"enc2Val"`
	OrigVal       frontend.Variable            `gnark:"origVal"`
	Pass2Deps     Pass2ReversalWitness         `gnark:"pass2Deps"`
	Pass1DepEnc2  [K + 1]frontend.Variable     `gnark:"pass1DepEnc2"`
	Pass1DepPass2 [K + 1]Pass2ReversalWitness  `gnark:"pass1DepPass2"`
}

// EnhancementChunkOpening holds enc2 elements and depth-30 proof for enhancement checks.
type EnhancementChunkOpening struct {
	Enc2Elements [NumFieldElements]frontend.Variable `gnark:"enc2Elements"`
	ReplicaProof shared.MerkleProof30                `gnark:"replicaProof"`
	SlotMapping  SlotMappingWitness                  `gnark:"slotMapping"`
}

// RouteWitness holds the full witness for one route.
type RouteWitness struct {
	Hops               [H]HopWitness               `gnark:"hops"`
	TerminusChunk      ChunkOpening                 `gnark:"terminusChunk"`
	TerminusElemIdx    frontend.Variable            `gnark:"terminusElemIdx"`
	FirstHopChunk      EnhancementChunkOpening      `gnark:"firstHopChunk"`
	IntermediateChunks [Q]EnhancementChunkOpening   `gnark:"intermediateChunks"`
}

// OriginWitness holds the origin chunk and its R routes.
type OriginWitness struct {
	Chunk           ChunkOpening      `gnark:"chunk"`
	LogicalChunkIdx frontend.Variable `gnark:"logicalChunkIdx"`
	Routes          [R]RouteWitness   `gnark:"routes"`
}

// ArchiveMURICircuit implements route-based DAG tracing verification.
type ArchiveMURICircuit struct {
	// Public inputs (4)
	ArchiveOriginalRoot frontend.Variable `gnark:"archiveOriginalRoot,public"`
	ArchiveReplicaRoot  frontend.Variable `gnark:"archiveReplicaRoot,public"`
	PublicKey           frontend.Variable `gnark:"publicKey,public"`
	ChallengeRandomness frontend.Variable `gnark:"challengeRandomness,public"`

	// Private inputs
	SlotTreeRoot    frontend.Variable        `gnark:"slotTreeRoot"`
	TotalRealChunks frontend.Variable        `gnark:"totalRealChunks"`
	GlobalR         frontend.Variable        `gnark:"globalR"`
	N               frontend.Variable        `gnark:"n"`
	Origins         [C]OriginWitness         `gnark:"origins"`
}

func (circuit *ArchiveMURICircuit) Define(api frontend.API) error {
	// ---------------------------------------------------------------
	// 1. Archive root binding
	// ---------------------------------------------------------------
	h := newHasher(api)
	h.Write(frontend.Variable(crypto.DomainTagArchiveRoot))
	h.Write(circuit.SlotTreeRoot)
	h.Write(circuit.TotalRealChunks)
	derivedOrigRoot := h.Sum()
	h.Reset()
	api.AssertIsEqual(circuit.ArchiveOriginalRoot, derivedOrigRoot)

	// Verify GlobalR
	h.Write(frontend.Variable(crypto.DomainTagGlobalR))
	h.Write(circuit.PublicKey)
	h.Write(circuit.ArchiveOriginalRoot)
	derivedR := h.Sum()
	h.Reset()
	api.AssertIsEqual(circuit.GlobalR, derivedR)

	// Verify N = totalRealChunks * ElementsPerChunk
	api.AssertIsEqual(circuit.N, api.Mul(circuit.TotalRealChunks, ElementsPerChunk))
	api.AssertIsEqual(api.IsZero(circuit.TotalRealChunks), 0)

	maxVal := new(big.Int).SetInt64(int64(1<<ArchiveTreeDepth)*int64(ElementsPerChunk) + 1)
	comparator := cmp.NewBoundedComparator(api, maxVal, false)

	// ---------------------------------------------------------------
	// 2. Precompute seed keys (constant across all hops, only depend on globalR)
	// ---------------------------------------------------------------
	h.Write(frontend.Variable(crypto.DomainTagKeySeed1))
	h.Write(circuit.GlobalR)
	keySeed1 := h.Sum()
	h.Reset()

	h.Write(frontend.Variable(crypto.DomainTagKeySeed2))
	h.Write(circuit.GlobalR)
	keySeed2 := h.Sum()
	h.Reset()

	// ---------------------------------------------------------------
	// 3. Per origin chunk
	// ---------------------------------------------------------------
	for c := 0; c < C; c++ {
		origin := &circuit.Origins[c]

		// Spot-check selection
		if c == 0 {
			api.AssertIsEqual(origin.LogicalChunkIdx, 0)
		} else {
			comparator.AssertIsLess(origin.LogicalChunkIdx, circuit.TotalRealChunks)
		}

		// Verify origin chunk (both trees)
		verifyChunkOpening(api, &origin.Chunk, origin.LogicalChunkIdx,
			circuit.SlotTreeRoot, circuit.ArchiveReplicaRoot, comparator)

		// Per route
		for i := 0; i < R; i++ {
			route := &origin.Routes[i]

			// Create one shared hasher per route for hop verification.
			// Reset between uses to reuse the Poseidon2 permutation state.
			hopHasher := newHasher(api)

			// Trace hops: dual-pass verification at each element (MURI.md Section 7.1)
			for hIdx := 0; hIdx < H; hIdx++ {
				hop := &route.Hops[hIdx]
				verifyHopDualPass(api, hopHasher, hop, circuit.GlobalR, circuit.N, keySeed1, keySeed2)
			}

			// Terminus verification
			terminusChunkIdx := api.Div(route.TerminusElemIdx, ElementsPerChunk)
			verifyChunkOpening(api, &route.TerminusChunk, terminusChunkIdx,
				circuit.SlotTreeRoot, circuit.ArchiveReplicaRoot, comparator)

			// First-hop enhancement
			verifyEnhancementChunk(api, &route.FirstHopChunk,
				circuit.ArchiveReplicaRoot, circuit.SlotTreeRoot)

			// Q intermediate enhancements
			for q := 0; q < Q; q++ {
				verifyEnhancementChunk(api, &route.IntermediateChunks[q],
					circuit.ArchiveReplicaRoot, circuit.SlotTreeRoot)
			}
		}
	}

	return nil
}

// verifyChunkOpening verifies a chunk against both original and replica trees.
func verifyChunkOpening(
	api frontend.API,
	chunk *ChunkOpening,
	logicalChunkIdx frontend.Variable,
	slotTreeRoot, archiveReplicaRoot frontend.Variable,
	comparator *cmp.BoundedComparator,
) {
	h := newHasher(api)

	// Slot leaf hash
	h.Write(frontend.Variable(crypto.DomainTagSlot))
	h.Write(chunk.SlotMapping.FileRoot)
	h.Write(chunk.SlotMapping.NumChunks)
	h.Write(chunk.SlotMapping.CumulativeChunks)
	slotLeafHash := h.Sum()
	h.Reset()

	api.AssertIsEqual(chunk.SlotMapping.SlotProof.LeafHash, slotLeafHash)
	slotRoot, _ := chunk.SlotMapping.SlotProof.ComputeRoot(api)
	api.AssertIsEqual(slotRoot, slotTreeRoot)

	// Range check
	localIdx := api.Sub(logicalChunkIdx, chunk.SlotMapping.CumulativeChunks)
	comparator.AssertIsLess(localIdx, chunk.SlotMapping.NumChunks)

	// Original leaf hash and depth-20 proof
	h.Write(frontend.Variable(crypto.DomainTagReal))
	h.Write(chunk.OrigElements[:]...)
	origLeafHash := h.Sum()
	h.Reset()
	api.AssertIsEqual(chunk.OrigProof.LeafHash, origLeafHash)
	origRoot, _ := chunk.OrigProof.ComputeRoot(api)
	api.AssertIsEqual(origRoot, chunk.SlotMapping.FileRoot)

	// Replica leaf hash and depth-30 proof
	h.Write(frontend.Variable(crypto.DomainTagReal))
	h.Write(chunk.Enc2Elements[:]...)
	replicaLeafHash := h.Sum()
	h.Reset()
	api.AssertIsEqual(chunk.ReplicaProof.LeafHash, replicaLeafHash)
	replicaRoot, _ := chunk.ReplicaProof.ComputeRoot(api)
	api.AssertIsEqual(replicaRoot, archiveReplicaRoot)
}

// verifyHopDualPass verifies the dual-pass sealing at element j (MURI.md Section 7.1).
//
// Pass 2 (R→L): key2[j] = H(DomainTagKeyElem2, enc2[j+1], enc2[bp2[0..k-1]], r)
//
//	or keySeed2 if j == N-1.
//	enc1[j] = enc2[j] - key2[j]
//
// Pass 1 (L→R): For each dep position p in {j-1, bp1[0..k-1]}:
//
//	derive enc1[p] = enc2[p] - key2[p]  (Pass 2 reversal)
//	key1[j] = H(DomainTagKeyElem1, enc1[j-1], enc1[bp1[0..k-1]], r)
//	or keySeed1 if j == 0.
//
// Assertion: enc2[j] == orig[j] + key1[j] + key2[j]  (mod p)
//
// keySeed1 and keySeed2 are precomputed once in Define() to avoid redundant hashing.
// h is a shared hasher (reused via Reset) to avoid allocating new Poseidon2 permutations.
func verifyHopDualPass(api frontend.API, h hash.FieldHasher, hop *HopWitness, globalR, N, keySeed1, keySeed2 frontend.Variable) {
	// Boundary detection
	isLastElem := api.IsZero(api.Sub(hop.ElemIdx, api.Sub(N, 1)))
	isFirstElem := api.IsZero(hop.ElemIdx)

	// ---- Pass 2: derive key2[j] ----
	key2 := deriveKey2InCircuit(api, h, isLastElem, &hop.Pass2Deps, globalR, keySeed2)

	// ---- Pass 1: derive key1[j] via enc1 at dependency positions ----
	// Each enc1[p] is derived from enc2[p] via Pass 2 reversal.
	var depEnc1 [K + 1]frontend.Variable
	for d := 0; d < K+1; d++ {
		depKey2 := deriveKey2InCircuit(api, h, hop.Pass1DepPass2[d].IsLastElem, &hop.Pass1DepPass2[d], globalR, keySeed2)
		depEnc1[d] = api.Sub(hop.Pass1DepEnc2[d], depKey2)
	}

	// Normal key1 = H(DomainTagKeyElem1, enc1[j-1], enc1[bp1[0..k-1]], r)
	h.Write(frontend.Variable(crypto.DomainTagKeyElem1))
	for d := 0; d < K+1; d++ {
		h.Write(depEnc1[d])
	}
	h.Write(globalR)
	keyNormal1 := h.Sum()
	h.Reset()

	key1 := api.Select(isFirstElem, keySeed1, keyNormal1)

	// ---- Dual-pass assertion ----
	// From the sealing transform (MURI.md Section 5.3-5.4):
	//   enc1[j] = orig[j] + key1[j]
	//   enc2[j] = enc1[j] + key2[j]
	// Therefore: enc2[j] = orig[j] + key1[j] + key2[j]
	api.AssertIsEqual(hop.Enc2Val, api.Add(hop.OrigVal, api.Add(key1, key2)))
}

// deriveKey2InCircuit derives the Pass 2 key for a single element.
// If isLastElem == 1, uses the precomputed keySeed2.
// Otherwise, uses H(DomainTagKeyElem2, enc2[j+1], enc2[bp2[0..k-1]], r).
// h is a shared hasher reused via Reset.
func deriveKey2InCircuit(api frontend.API, h hash.FieldHasher, isLastElem frontend.Variable, deps *Pass2ReversalWitness, globalR, keySeed2 frontend.Variable) frontend.Variable {
	// Normal key2 = H(DomainTagKeyElem2, enc2[j+1], enc2[bp2[0..k-1]], r)
	h.Write(frontend.Variable(crypto.DomainTagKeyElem2))
	h.Write(deps.Enc2Next)
	for m := 0; m < K; m++ {
		h.Write(deps.Enc2BPs[m])
	}
	h.Write(globalR)
	keyNormal := h.Sum()
	h.Reset()

	return api.Select(isLastElem, keySeed2, keyNormal)
}

// verifyEnhancementChunk verifies an enhancement chunk's depth-30 proof.
func verifyEnhancementChunk(
	api frontend.API,
	chunk *EnhancementChunkOpening,
	archiveReplicaRoot, slotTreeRoot frontend.Variable,
) {
	h := newHasher(api)

	// Slot mapping
	h.Write(frontend.Variable(crypto.DomainTagSlot))
	h.Write(chunk.SlotMapping.FileRoot)
	h.Write(chunk.SlotMapping.NumChunks)
	h.Write(chunk.SlotMapping.CumulativeChunks)
	slotLeafHash := h.Sum()
	h.Reset()

	api.AssertIsEqual(chunk.SlotMapping.SlotProof.LeafHash, slotLeafHash)
	slotRoot, _ := chunk.SlotMapping.SlotProof.ComputeRoot(api)
	api.AssertIsEqual(slotRoot, slotTreeRoot)

	// Replica leaf hash and depth-30 proof
	h.Write(frontend.Variable(crypto.DomainTagReal))
	h.Write(chunk.Enc2Elements[:]...)
	replicaLeafHash := h.Sum()
	h.Reset()
	api.AssertIsEqual(chunk.ReplicaProof.LeafHash, replicaLeafHash)
	replicaRoot, _ := chunk.ReplicaProof.ComputeRoot(api)
	api.AssertIsEqual(replicaRoot, archiveReplicaRoot)
}

// Ensure imports
var _ = archive.ArchiveIndexDepth

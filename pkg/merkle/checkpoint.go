package merkle

import (
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"runtime"
	"sync"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// ---------------------------------------------------------------------------
// Checkpointed Sparse Merkle Tree
// ---------------------------------------------------------------------------
//
// A CheckpointedSMT persists only selected "checkpoint" levels of the full
// sparse Merkle tree. At proof time the gaps between checkpoints are rebuilt
// in parallel:
//
//   - Bottom gap (level 0 → first checkpoint): re-reads chunks from storage
//     and parallel-hashes them using a worker pool (the expensive step).
//   - Middle/upper gaps: rebuild from stored checkpoint entries via cheap
//     HashNodes calls (each gap in its own goroutine).
//
// Graduated spacing — smaller gaps near the bottom, larger near the top —
// equalises per-gap rebuild cost so that wall-clock time ≈ max(gap_times)
// rather than sum(gap_times).

// CheckpointScheme defines which SMT levels to persist.
// Levels must be sorted ascending with the last element equal to the tree
// depth. Presets below target depth-20 trees (MaxTreeDepth in the PoI circuit).
type CheckpointScheme struct {
	Levels []int
}

// Preset checkpoint schemes for depth-20 trees.
//
// Space estimates assume a 10 GB file (655 360 chunks of 16 KB).
// Rebuild time assumes 11 CPU cores and ~4 ms per Poseidon2 leaf hash.
var (
	// SchemeCompact stores only level 10 and root.
	// Space: ~23 KB. Rebuild: ~400 ms/opening.
	SchemeCompact = CheckpointScheme{Levels: []int{10, 20}}

	// SchemeBalanced stores 4 checkpoint levels with graduated gaps (4,5,6,5).
	// Space: ~1.5 MB. Rebuild: ~6 ms/opening.
	SchemeBalanced = CheckpointScheme{Levels: []int{4, 9, 15, 20}}

	// SchemeFast stores 4 checkpoint levels with smaller bottom gap (3,4,5,8).
	// Space: ~3.1 MB. Rebuild: ~3 ms/opening.
	SchemeFast = CheckpointScheme{Levels: []int{3, 7, 12, 20}}
)

// CheckpointedSMT holds only the entries at checkpoint levels plus the
// precomputed zero-subtree hash chain.
type CheckpointedSMT struct {
	Root       *big.Int
	Depth      int
	NumLeaves  int
	Scheme     CheckpointScheme
	Levels     map[int]map[int]*big.Int // checkpoint level → index → hash
	ZeroHashes []*big.Int
}

// RebuildProofResult holds the output of CheckpointedSMT.RebuildProof.
type RebuildProofResult struct {
	Siblings   []*big.Int
	Directions []int
	LeafHash   *big.Int
}

// segment is a contiguous range of tree levels [lo, hi) that must be
// rebuilt from the entries at level lo.
type segment struct {
	lo, hi      int
	needsChunks bool // true when level lo is not stored (bottom gap)
}

// ---------------------------------------------------------------------------
// Serialization
// ---------------------------------------------------------------------------
//
// Binary format:
//   uint32(depth) | uint32(numLeaves) | uint32(numCheckpointLevels)
//   uint32(level_0) | uint32(level_1) | ... | uint32(level_k)
//   For each checkpoint level (in scheme order):
//     uint32(count)
//     For each entry (sorted by index):
//       uint32(index) | [32]byte(hash as big-endian fr.Element)

// SaveCheckpointed writes only the checkpoint-level entries of the full SMT.
func (smt *SparseMerkleTree) SaveCheckpointed(w io.Writer, scheme CheckpointScheme) error {
	if err := validateScheme(scheme, smt.Depth); err != nil {
		return err
	}

	// Header.
	if err := binary.Write(w, binary.BigEndian, uint32(smt.Depth)); err != nil {
		return fmt.Errorf("write depth: %w", err)
	}
	if err := binary.Write(w, binary.BigEndian, uint32(smt.NumLeaves)); err != nil {
		return fmt.Errorf("write numLeaves: %w", err)
	}
	if err := binary.Write(w, binary.BigEndian, uint32(len(scheme.Levels))); err != nil {
		return fmt.Errorf("write level count: %w", err)
	}
	for _, lvl := range scheme.Levels {
		if err := binary.Write(w, binary.BigEndian, uint32(lvl)); err != nil {
			return fmt.Errorf("write level number: %w", err)
		}
	}

	// Per-checkpoint-level entries.
	for _, lvl := range scheme.Levels {
		m := smt.Levels[lvl]
		if err := binary.Write(w, binary.BigEndian, uint32(len(m))); err != nil {
			return fmt.Errorf("write level %d count: %w", lvl, err)
		}
		indices := make([]int, 0, len(m))
		for idx := range m {
			indices = append(indices, idx)
		}
		sortInts(indices)
		for _, idx := range indices {
			if err := binary.Write(w, binary.BigEndian, uint32(idx)); err != nil {
				return fmt.Errorf("write level %d index: %w", lvl, err)
			}
			var elem fr.Element
			elem.SetBigInt(m[idx])
			b := elem.Bytes()
			if _, err := w.Write(b[:]); err != nil {
				return fmt.Errorf("write level %d hash: %w", lvl, err)
			}
		}
	}
	return nil
}

// LoadCheckpointedSMT reads a checkpointed SMT written by SaveCheckpointed.
// zeroLeafHash is needed to rebuild the zero-subtree hash chain.
func LoadCheckpointedSMT(r io.Reader, zeroLeafHash *big.Int) (*CheckpointedSMT, error) {
	var depth, numLeaves, numLevels uint32
	if err := binary.Read(r, binary.BigEndian, &depth); err != nil {
		return nil, fmt.Errorf("read depth: %w", err)
	}
	if err := binary.Read(r, binary.BigEndian, &numLeaves); err != nil {
		return nil, fmt.Errorf("read numLeaves: %w", err)
	}
	if err := binary.Read(r, binary.BigEndian, &numLevels); err != nil {
		return nil, fmt.Errorf("read level count: %w", err)
	}

	checkpointLevels := make([]int, numLevels)
	for i := range checkpointLevels {
		var lvl uint32
		if err := binary.Read(r, binary.BigEndian, &lvl); err != nil {
			return nil, fmt.Errorf("read level number: %w", err)
		}
		checkpointLevels[i] = int(lvl)
	}

	zeroHashes := PrecomputeZeroHashes(int(depth), zeroLeafHash)

	levels := make(map[int]map[int]*big.Int, int(numLevels))
	for _, lvl := range checkpointLevels {
		var count uint32
		if err := binary.Read(r, binary.BigEndian, &count); err != nil {
			return nil, fmt.Errorf("read level %d count: %w", lvl, err)
		}
		m := make(map[int]*big.Int, int(count))
		var hashBuf [32]byte
		for j := 0; j < int(count); j++ {
			var idx uint32
			if err := binary.Read(r, binary.BigEndian, &idx); err != nil {
				return nil, fmt.Errorf("read level %d index: %w", lvl, err)
			}
			if _, err := io.ReadFull(r, hashBuf[:]); err != nil {
				return nil, fmt.Errorf("read level %d hash: %w", lvl, err)
			}
			var elem fr.Element
			elem.SetBytes(hashBuf[:])
			m[int(idx)] = new(big.Int)
			elem.BigInt(m[int(idx)])
		}
		levels[lvl] = m
	}

	// Root is at levels[depth][0], or the zero hash for an empty tree.
	root := zeroHashes[depth]
	if rootLevel, ok := levels[int(depth)]; ok {
		if r, ok := rootLevel[0]; ok {
			root = r
		}
	}

	return &CheckpointedSMT{
		Root:       root,
		Depth:      int(depth),
		NumLeaves:  int(numLeaves),
		Scheme:     CheckpointScheme{Levels: checkpointLevels},
		Levels:     levels,
		ZeroHashes: zeroHashes,
	}, nil
}

// ---------------------------------------------------------------------------
// Parallel proof reconstruction
// ---------------------------------------------------------------------------

// RebuildProof reconstructs a full depth-sized Merkle proof by rebuilding
// the gaps between checkpoint levels in parallel.
//
// readChunk provides raw chunk data for the bottom gap; it is called only
// for indices in [0, NumLeaves). hashLeaf hashes a chunk to produce the
// leaf-level hash (same function used during tree construction).
//
// The returned LeafHash is the hash at leafIndex (recomputed if necessary,
// or the zero leaf hash for padding positions).
func (csmt *CheckpointedSMT) RebuildProof(leafIndex int, readChunk func(int) []byte, hashLeaf HashFunc) *RebuildProofResult {
	siblings := make([]*big.Int, csmt.Depth)
	directions := make([]int, csmt.Depth)

	// Compute directions (identical to SparseMerkleTree.GetProof).
	idx := leafIndex
	for lvl := 0; lvl < csmt.Depth; lvl++ {
		if idx%2 == 0 {
			directions[lvl] = 0
		} else {
			directions[lvl] = 1
		}
		idx /= 2
	}

	// Build segment list from checkpoint boundaries.
	segments := csmt.buildSegments()

	// Per-segment results. Each goroutine writes to its own slot.
	type segResult struct {
		siblings map[int]*big.Int // absLevel → sibling hash
		leafHash *big.Int         // set only by the bottom segment
	}
	results := make([]segResult, len(segments))

	// Launch one goroutine per segment.
	var wg sync.WaitGroup
	for si, seg := range segments {
		wg.Add(1)
		go func(si int, seg segment) {
			defer wg.Done()
			gapDepth := seg.hi - seg.lo
			if gapDepth == 0 {
				return
			}

			// Identify the subtree region at the base level.
			subtreeAtHi := leafIndex >> seg.hi
			baseStart := subtreeAtHi << gapDepth
			subtreeSize := 1 << gapDepth

			// Populate base-level entries for this subtree.
			baseEntries := make(map[int]*big.Int)
			var segLeafHash *big.Int

			if seg.needsChunks {
				// Bottom gap: parallel leaf hashing from chunk data.
				baseEntries, segLeafHash = csmt.rebuildBottomEntries(
					baseStart, subtreeSize, leafIndex, readChunk, hashLeaf, len(segments),
				)
			} else {
				// Middle/upper gap: look up stored entries at the base level.
				if stored, ok := csmt.Levels[seg.lo]; ok {
					for i := 0; i < subtreeSize; i++ {
						absIdx := baseStart + i
						if h, ok := stored[absIdx]; ok {
							baseEntries[absIdx] = h
						}
					}
				}
				// If this segment covers level 0 (leaves are stored),
				// extract the leaf hash directly.
				if seg.lo == 0 {
					if h, ok := baseEntries[leafIndex]; ok {
						segLeafHash = h
					} else {
						segLeafHash = csmt.ZeroHashes[0]
					}
				}
			}

			// Build upward through the gap, extracting siblings at each level.
			segSiblings := csmt.buildGap(baseEntries, seg.lo, gapDepth, leafIndex)

			results[si].siblings = segSiblings
			results[si].leafHash = segLeafHash
		}(si, seg)
	}
	wg.Wait()

	// Assemble final siblings and leaf hash from segment results.
	var leafHash *big.Int
	for _, res := range results {
		for lvl, sib := range res.siblings {
			siblings[lvl] = sib
		}
		if res.leafHash != nil {
			leafHash = res.leafHash
		}
	}

	// Fill any remaining nil siblings with zero hashes (e.g. if a segment
	// produced no entries for certain levels due to empty subtrees).
	for i, s := range siblings {
		if s == nil {
			siblings[i] = csmt.ZeroHashes[i]
		}
	}
	if leafHash == nil {
		leafHash = csmt.ZeroHashes[0]
	}

	return &RebuildProofResult{
		Siblings:   siblings,
		Directions: directions,
		LeafHash:   leafHash,
	}
}

// buildSegments partitions the tree levels into contiguous segments bounded
// by consecutive checkpoint levels.
func (csmt *CheckpointedSMT) buildSegments() []segment {
	_, hasLevel0 := csmt.Levels[0]
	var segments []segment
	prev := 0
	for _, cp := range csmt.Scheme.Levels {
		if cp > prev {
			segments = append(segments, segment{
				lo:          prev,
				hi:          cp,
				needsChunks: prev == 0 && !hasLevel0,
			})
		}
		prev = cp
	}
	return segments
}

// rebuildBottomEntries hashes chunks in parallel for the bottom gap.
// Returns the base-level entries map and the leaf hash at leafIndex.
func (csmt *CheckpointedSMT) rebuildBottomEntries(
	baseStart, subtreeSize, leafIndex int,
	readChunk func(int) []byte,
	hashLeaf HashFunc,
	numSegments int,
) (map[int]*big.Int, *big.Int) {
	hashes := make([]*big.Int, subtreeSize)

	// Worker pool: reserve one core per non-bottom segment so they can
	// run truly in parallel with the leaf hashing.
	numWorkers := runtime.NumCPU()
	if numSegments > 1 && numWorkers > numSegments {
		numWorkers -= numSegments - 1
	}
	if numWorkers > subtreeSize {
		numWorkers = subtreeSize
	}
	if numWorkers < 1 {
		numWorkers = 1
	}

	var leafWg sync.WaitGroup
	work := make(chan int, subtreeSize)
	for w := 0; w < numWorkers; w++ {
		leafWg.Add(1)
		go func() {
			defer leafWg.Done()
			for localIdx := range work {
				absIdx := baseStart + localIdx
				if absIdx < csmt.NumLeaves {
					hashes[localIdx] = hashLeaf(readChunk(absIdx))
				}
				// nil entries → zero leaf hash (handled during gap build)
			}
		}()
	}
	for i := 0; i < subtreeSize; i++ {
		work <- i
	}
	close(work)
	leafWg.Wait()

	// Collect into base entries map.
	baseEntries := make(map[int]*big.Int, subtreeSize)
	for i, h := range hashes {
		if h != nil {
			baseEntries[baseStart+i] = h
		}
	}

	// Extract the leaf hash.
	localOffset := leafIndex - baseStart
	var leafHash *big.Int
	if localOffset >= 0 && localOffset < subtreeSize && hashes[localOffset] != nil {
		leafHash = hashes[localOffset]
	} else {
		leafHash = csmt.ZeroHashes[0]
	}

	return baseEntries, leafHash
}

// buildGap constructs intermediate levels from baseEntries and extracts the
// sibling hash at each level for the proof path of leafIndex.
func (csmt *CheckpointedSMT) buildGap(
	baseEntries map[int]*big.Int,
	baseLvl, gapDepth, leafIndex int,
) map[int]*big.Int {
	segSiblings := make(map[int]*big.Int, gapDepth)
	currentEntries := baseEntries

	for relLvl := 0; relLvl < gapDepth; relLvl++ {
		absLvl := baseLvl + relLvl

		// Extract sibling at this level.
		nodeIdx := leafIndex >> absLvl
		sibIdx := nodeIdx ^ 1
		if h, ok := currentEntries[sibIdx]; ok {
			segSiblings[absLvl] = h
		} else {
			segSiblings[absLvl] = csmt.ZeroHashes[absLvl]
		}

		// Build next level from current entries.
		nextEntries := make(map[int]*big.Int)
		parentIndices := make(map[int]bool)
		for idx := range currentEntries {
			parentIndices[idx/2] = true
		}
		for parentIdx := range parentIndices {
			leftIdx := parentIdx * 2
			rightIdx := parentIdx*2 + 1

			left, ok := currentEntries[leftIdx]
			if !ok {
				left = csmt.ZeroHashes[absLvl]
			}
			right, ok := currentEntries[rightIdx]
			if !ok {
				right = csmt.ZeroHashes[absLvl]
			}
			nextEntries[parentIdx] = HashNodes(left, right)
		}
		currentEntries = nextEntries
	}

	return segSiblings
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

func validateScheme(scheme CheckpointScheme, depth int) error {
	if len(scheme.Levels) == 0 {
		return fmt.Errorf("checkpoint scheme has no levels")
	}
	if scheme.Levels[len(scheme.Levels)-1] != depth {
		return fmt.Errorf("checkpoint scheme must end with tree depth %d, got %d",
			depth, scheme.Levels[len(scheme.Levels)-1])
	}
	for i := 1; i < len(scheme.Levels); i++ {
		if scheme.Levels[i] <= scheme.Levels[i-1] {
			return fmt.Errorf("checkpoint levels must be sorted ascending: %d <= %d",
				scheme.Levels[i], scheme.Levels[i-1])
		}
	}
	if scheme.Levels[0] < 0 {
		return fmt.Errorf("checkpoint levels must be non-negative")
	}
	return nil
}

package merkle

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"

	"github.com/MuriData/muri-zkproof/pkg/crypto"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

const (
	testElementSize = 31
	testChunkSize   = testElementSize * 528 // 16368 bytes ≈ 16 KB chunk
	testMaxDepth    = 20
)

// testHashChunk is a deterministic leaf hash function for testing.
// Uses Poseidon2 sponge with DomainTagReal and randomness = 1.
// Returns fr.Element directly (no *big.Int conversion).
func testHashChunk(chunk []byte) fr.Element {
	return crypto.HashLeafFr(crypto.DomainTagReal, chunk, testElementSize, 528)
}

// testZeroLeafHash computes the zero leaf hash (domain tag = 0, all zeros).
func testZeroLeafHash() fr.Element {
	return crypto.ComputeZeroLeafHashFr(testElementSize, 528)
}

// TestSparseMerkleParallel verifies that the parallel leaf hashing in
// GenerateSparseMerkleTree produces the same root as sequential hashing.
func TestSparseMerkleParallel(t *testing.T) {
	chunkCounts := []int{1, 2, 4, 8, 16}

	for _, n := range chunkCounts {
		t.Run(fmtChunks(n), func(t *testing.T) {
			data := make([]byte, n*testChunkSize)
			if _, err := rand.Read(data); err != nil {
				t.Fatal(err)
			}
			chunks := SplitIntoChunks(data, testChunkSize)
			zeroLeaf := testZeroLeafHash()

			// Build SMT (uses parallel hashing internally).
			smt, err := GenerateSparseMerkleTree(chunks, testMaxDepth, testHashChunk, zeroLeaf)
			if err != nil {
				t.Fatalf("build SMT: %v", err)
			}

			// Recompute leaf hashes sequentially for comparison.
			seqLeafHashes := make([]fr.Element, len(chunks))
			for i, c := range chunks {
				seqLeafHashes[i] = testHashChunk(c)
			}

			// Verify leaf hashes match.
			for i, h := range seqLeafHashes {
				got := smt.GetLeafHash(i)
				if got != h {
					t.Fatalf("leaf %d hash mismatch", i)
				}
			}

			// Verify root is non-zero.
			var zero fr.Element
			if smt.Root == zero {
				t.Fatal("root hash is zero")
			}

			// Verify proof for first leaf.
			siblings, _ := smt.GetProof(0)
			if len(siblings) != testMaxDepth {
				t.Fatalf("proof length %d, want %d", len(siblings), testMaxDepth)
			}

			rootBytes := smt.Root.Bytes()
			t.Logf("chunks=%d root=0x%x...", n, rootBytes[:8])
		})
	}
}

// TestSMTSaveLoad verifies Save/LoadSparseMerkleTree round-trip fidelity.
func TestSMTSaveLoad(t *testing.T) {
	chunkCounts := []int{1, 4, 8}

	for _, n := range chunkCounts {
		t.Run(fmtChunks(n), func(t *testing.T) {
			data := make([]byte, n*testChunkSize)
			if _, err := rand.Read(data); err != nil {
				t.Fatal(err)
			}
			chunks := SplitIntoChunks(data, testChunkSize)
			zeroLeaf := testZeroLeafHash()

			original, err := GenerateSparseMerkleTree(chunks, testMaxDepth, testHashChunk, zeroLeaf)
			if err != nil {
				t.Fatalf("build SMT: %v", err)
			}

			// Serialize.
			var buf bytes.Buffer
			if err := original.Save(&buf); err != nil {
				t.Fatalf("save: %v", err)
			}
			serializedSize := buf.Len()
			t.Logf("chunks=%d serialized=%d bytes", n, serializedSize)

			// Deserialize.
			loaded, err := LoadSparseMerkleTree(&buf, zeroLeaf)
			if err != nil {
				t.Fatalf("load: %v", err)
			}

			// Verify fields.
			if loaded.Depth != original.Depth {
				t.Fatalf("depth: got %d, want %d", loaded.Depth, original.Depth)
			}
			if loaded.NumLeaves != original.NumLeaves {
				t.Fatalf("numLeaves: got %d, want %d", loaded.NumLeaves, original.NumLeaves)
			}
			if loaded.Root != original.Root {
				t.Fatalf("root mismatch")
			}

			// Verify all level entries match.
			for lvl := 0; lvl <= original.Depth; lvl++ {
				origSlice := original.Levels[lvl]
				loadSlice := loaded.Levels[lvl]
				if len(origSlice) != len(loadSlice) {
					t.Fatalf("level %d: entry count %d != %d", lvl, len(loadSlice), len(origSlice))
				}
				for idx, origHash := range origSlice {
					if origHash != loadSlice[idx] {
						t.Fatalf("level %d index %d: hash mismatch", lvl, idx)
					}
				}
			}

			// Verify proofs still work after load.
			for i := 0; i < n && i < 4; i++ {
				origSib, origDir := original.GetProof(i)
				loadSib, loadDir := loaded.GetProof(i)
				for j := 0; j < testMaxDepth; j++ {
					if origSib[j] != loadSib[j] {
						t.Fatalf("proof[%d] sibling[%d] mismatch", i, j)
					}
					if origDir[j] != loadDir[j] {
						t.Fatalf("proof[%d] direction[%d] mismatch", i, j)
					}
				}
			}
		})
	}
}

// TestSMTSaveLoadEmpty verifies Save/Load handles an empty tree.
func TestSMTSaveLoadEmpty(t *testing.T) {
	zeroLeaf := testZeroLeafHash()
	original, err := GenerateSparseMerkleTree(nil, testMaxDepth, testHashChunk, zeroLeaf)
	if err != nil {
		t.Fatalf("build SMT: %v", err)
	}

	var buf bytes.Buffer
	if err := original.Save(&buf); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := LoadSparseMerkleTree(&buf, zeroLeaf)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if loaded.Root != original.Root {
		t.Fatalf("root mismatch for empty tree")
	}
	if loaded.NumLeaves != 0 {
		t.Fatalf("numLeaves: got %d, want 0", loaded.NumLeaves)
	}
}

func TestGenerateSparseMerkleTreeRejectsTooManyLeaves(t *testing.T) {
	chunks := [][]byte{
		make([]byte, testChunkSize),
		make([]byte, testChunkSize),
		make([]byte, testChunkSize),
	}

	_, err := GenerateSparseMerkleTree(chunks, 1, testHashChunk, testZeroLeafHash())
	if err == nil {
		t.Fatal("expected oversized tree error")
	}
	if !strings.Contains(err.Error(), "supports at most 2 leaves") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestBuildSMTFromLeafHashesRejectsTooManyLeaves(t *testing.T) {
	var a, b, c fr.Element
	a.SetInt64(1)
	b.SetInt64(2)
	c.SetInt64(3)
	leafHashes := []fr.Element{a, b, c}

	_, err := BuildSMTFromLeafHashes(leafHashes, 1, testZeroLeafHash())
	if err == nil {
		t.Fatal("expected oversized tree error")
	}
	if !strings.Contains(err.Error(), "supports at most 2 leaves") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func BenchmarkSMTConstruction(b *testing.B) {
	// 8 chunks ≈ 128 KB (same as the standard PoI test).
	data := make([]byte, 8*testChunkSize)
	if _, err := rand.Read(data); err != nil {
		b.Fatal(err)
	}
	chunks := SplitIntoChunks(data, testChunkSize)
	zeroLeaf := testZeroLeafHash()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := GenerateSparseMerkleTree(chunks, testMaxDepth, testHashChunk, zeroLeaf); err != nil {
			b.Fatalf("build SMT: %v", err)
		}
	}
}

func BenchmarkSMTSaveLoad(b *testing.B) {
	data := make([]byte, 8*testChunkSize)
	if _, err := rand.Read(data); err != nil {
		b.Fatal(err)
	}
	chunks := SplitIntoChunks(data, testChunkSize)
	zeroLeaf := testZeroLeafHash()
	smt, err := GenerateSparseMerkleTree(chunks, testMaxDepth, testHashChunk, zeroLeaf)
	if err != nil {
		b.Fatalf("build SMT: %v", err)
	}

	b.Run("Save", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			var buf bytes.Buffer
			_ = smt.Save(&buf)
		}
	})

	var serialized bytes.Buffer
	_ = smt.Save(&serialized)
	serializedBytes := serialized.Bytes()

	b.Run("Load", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			r := bytes.NewReader(serializedBytes)
			_, _ = LoadSparseMerkleTree(r, zeroLeaf)
		}
	})
}

// ---------------------------------------------------------------------------
// Checkpointed SMT tests
// ---------------------------------------------------------------------------

// TestCheckpointedRebuildProof verifies that RebuildProof produces siblings
// identical to the full SparseMerkleTree.GetProof for all preset schemes.
func TestCheckpointedRebuildProof(t *testing.T) {
	schemes := []struct {
		name   string
		scheme CheckpointScheme
	}{
		{"Compact", SchemeCompact},
		{"Balanced", SchemeBalanced},
		{"Fast", SchemeFast},
	}

	chunkCounts := []int{1, 4, 8, 16}

	for _, sc := range schemes {
		for _, n := range chunkCounts {
			t.Run(sc.name+"/chunks_"+itoa(n), func(t *testing.T) {
				data := make([]byte, n*testChunkSize)
				if _, err := rand.Read(data); err != nil {
					t.Fatal(err)
				}
				chunks := SplitIntoChunks(data, testChunkSize)
				zeroLeaf := testZeroLeafHash()

				fullSMT, err := GenerateSparseMerkleTree(chunks, testMaxDepth, testHashChunk, zeroLeaf)
				if err != nil {
					t.Fatalf("build SMT: %v", err)
				}

				// Save as checkpointed, load back.
				var buf bytes.Buffer
				if err := fullSMT.SaveCheckpointed(&buf, sc.scheme); err != nil {
					t.Fatalf("save checkpointed: %v", err)
				}
				serialized := buf.Len()
				t.Logf("scheme=%s chunks=%d serialized=%d bytes", sc.name, n, serialized)

				csmt, err := LoadCheckpointedSMT(bytes.NewReader(buf.Bytes()), zeroLeaf)
				if err != nil {
					t.Fatalf("load checkpointed: %v", err)
				}

				// Verify root matches.
				if csmt.Root != fullSMT.Root {
					t.Fatalf("root mismatch")
				}

				readChunk := func(i int) []byte { return chunks[i] }

				// Test several leaf indices.
				for leafIdx := 0; leafIdx < n && leafIdx < 8; leafIdx++ {
					fullSib, fullDir := fullSMT.GetProof(leafIdx)
					result := csmt.RebuildProof(leafIdx, readChunk, testHashChunk)

					for lvl := 0; lvl < testMaxDepth; lvl++ {
						if fullSib[lvl] != result.Siblings[lvl] {
							t.Fatalf("leaf %d: sibling mismatch at level %d",
								leafIdx, lvl)
						}
						if fullDir[lvl] != result.Directions[lvl] {
							t.Fatalf("leaf %d: direction mismatch at level %d", leafIdx, lvl)
						}
					}

					expectedLeaf := fullSMT.GetLeafHash(leafIdx)
					if expectedLeaf != result.LeafHash {
						t.Fatalf("leaf %d: leaf hash mismatch", leafIdx)
					}
				}
			})
		}
	}
}

// TestCheckpointedSaveLoad verifies serialization round-trip fidelity.
func TestCheckpointedSaveLoad(t *testing.T) {
	data := make([]byte, 8*testChunkSize)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	chunks := SplitIntoChunks(data, testChunkSize)
	zeroLeaf := testZeroLeafHash()
	fullSMT, err := GenerateSparseMerkleTree(chunks, testMaxDepth, testHashChunk, zeroLeaf)
	if err != nil {
		t.Fatalf("build SMT: %v", err)
	}

	for _, scheme := range []struct {
		name string
		s    CheckpointScheme
	}{
		{"Compact", SchemeCompact},
		{"Balanced", SchemeBalanced},
		{"Fast", SchemeFast},
	} {
		t.Run(scheme.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := fullSMT.SaveCheckpointed(&buf, scheme.s); err != nil {
				t.Fatalf("save: %v", err)
			}
			raw := buf.Bytes()

			csmt, err := LoadCheckpointedSMT(bytes.NewReader(raw), zeroLeaf)
			if err != nil {
				t.Fatalf("load: %v", err)
			}

			if csmt.Depth != testMaxDepth {
				t.Fatalf("depth: got %d want %d", csmt.Depth, testMaxDepth)
			}
			if csmt.NumLeaves != len(chunks) {
				t.Fatalf("numLeaves: got %d want %d", csmt.NumLeaves, len(chunks))
			}
			if csmt.Root != fullSMT.Root {
				t.Fatalf("root mismatch")
			}

			// Verify every stored entry matches the full SMT.
			for _, lvl := range scheme.s.Levels {
				stored := csmt.Levels[lvl]
				full := fullSMT.Levels[lvl]
				if len(stored) != len(full) {
					t.Fatalf("level %d: count %d != %d", lvl, len(stored), len(full))
				}
				for idx, sh := range stored {
					if sh != full[idx] {
						t.Fatalf("level %d index %d: hash mismatch", lvl, idx)
					}
				}
			}

			t.Logf("scheme=%s serialized=%d bytes levels=%v", scheme.name, len(raw), scheme.s.Levels)
		})
	}
}

// TestCheckpointedPaddingLeaf verifies proofs for leaf indices in the
// padding region (>= NumLeaves) produce correct zero-based proofs.
func TestCheckpointedPaddingLeaf(t *testing.T) {
	data := make([]byte, 4*testChunkSize)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	chunks := SplitIntoChunks(data, testChunkSize)
	zeroLeaf := testZeroLeafHash()

	fullSMT, err := GenerateSparseMerkleTree(chunks, testMaxDepth, testHashChunk, zeroLeaf)
	if err != nil {
		t.Fatalf("build SMT: %v", err)
	}
	var buf bytes.Buffer
	if err := fullSMT.SaveCheckpointed(&buf, SchemeBalanced); err != nil {
		t.Fatalf("save: %v", err)
	}
	csmt, err := LoadCheckpointedSMT(bytes.NewReader(buf.Bytes()), zeroLeaf)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	readChunk := func(i int) []byte { return chunks[i] }

	// Test several padding indices — well beyond the 4 real leaves.
	for _, paddingIdx := range []int{100, 1000, 65536} {
		t.Run(itoa(paddingIdx), func(t *testing.T) {
			fullSib, fullDir := fullSMT.GetProof(paddingIdx)
			result := csmt.RebuildProof(paddingIdx, readChunk, testHashChunk)

			for lvl := 0; lvl < testMaxDepth; lvl++ {
				if fullSib[lvl] != result.Siblings[lvl] {
					t.Fatalf("padding leaf %d: sibling mismatch at level %d", paddingIdx, lvl)
				}
				if fullDir[lvl] != result.Directions[lvl] {
					t.Fatalf("padding leaf %d: direction mismatch at level %d", paddingIdx, lvl)
				}
			}

			if result.LeafHash != zeroLeaf {
				t.Fatalf("padding leaf %d: leaf hash should be zero leaf hash", paddingIdx)
			}
		})
	}
}

// TestCheckpointedSchemeLeavesOnly verifies a scheme that includes level 0
// (no chunk re-reading needed at rebuild time).
func TestCheckpointedSchemeLeavesOnly(t *testing.T) {
	leavesOnly := CheckpointScheme{Levels: []int{0, 10, 20}}

	data := make([]byte, 8*testChunkSize)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	chunks := SplitIntoChunks(data, testChunkSize)
	zeroLeaf := testZeroLeafHash()

	fullSMT, err := GenerateSparseMerkleTree(chunks, testMaxDepth, testHashChunk, zeroLeaf)
	if err != nil {
		t.Fatalf("build SMT: %v", err)
	}

	var buf bytes.Buffer
	if err := fullSMT.SaveCheckpointed(&buf, leavesOnly); err != nil {
		t.Fatalf("save: %v", err)
	}
	csmt, err := LoadCheckpointedSMT(bytes.NewReader(buf.Bytes()), zeroLeaf)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	// readChunk should never be called when level 0 is stored.
	readChunk := func(i int) []byte {
		t.Fatal("readChunk should not be called when level 0 is stored")
		return nil
	}

	for leafIdx := 0; leafIdx < 8; leafIdx++ {
		fullSib, _ := fullSMT.GetProof(leafIdx)
		result := csmt.RebuildProof(leafIdx, readChunk, testHashChunk)

		for lvl := 0; lvl < testMaxDepth; lvl++ {
			if fullSib[lvl] != result.Siblings[lvl] {
				t.Fatalf("leaf %d: sibling mismatch at level %d", leafIdx, lvl)
			}
		}

		expectedLeaf := fullSMT.GetLeafHash(leafIdx)
		if expectedLeaf != result.LeafHash {
			t.Fatalf("leaf %d: leaf hash mismatch", leafIdx)
		}
	}
}

// TestCheckpointedEmpty verifies the checkpoint system handles empty trees.
func TestCheckpointedEmpty(t *testing.T) {
	zeroLeaf := testZeroLeafHash()
	fullSMT, err := GenerateSparseMerkleTree(nil, testMaxDepth, testHashChunk, zeroLeaf)
	if err != nil {
		t.Fatalf("build SMT: %v", err)
	}

	var buf bytes.Buffer
	if err := fullSMT.SaveCheckpointed(&buf, SchemeBalanced); err != nil {
		t.Fatalf("save: %v", err)
	}
	csmt, err := LoadCheckpointedSMT(bytes.NewReader(buf.Bytes()), zeroLeaf)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if csmt.Root != fullSMT.Root {
		t.Fatalf("root mismatch for empty tree")
	}
}

func BenchmarkCheckpointedRebuildProof(b *testing.B) {
	data := make([]byte, 8*testChunkSize)
	if _, err := rand.Read(data); err != nil {
		b.Fatal(err)
	}
	chunks := SplitIntoChunks(data, testChunkSize)
	zeroLeaf := testZeroLeafHash()
	fullSMT, err := GenerateSparseMerkleTree(chunks, testMaxDepth, testHashChunk, zeroLeaf)
	if err != nil {
		b.Fatalf("build SMT: %v", err)
	}

	readChunk := func(i int) []byte { return chunks[i] }

	for _, scheme := range []struct {
		name string
		s    CheckpointScheme
	}{
		{"Compact", SchemeCompact},
		{"Balanced", SchemeBalanced},
		{"Fast", SchemeFast},
	} {
		var buf bytes.Buffer
		_ = fullSMT.SaveCheckpointed(&buf, scheme.s)
		csmt, _ := LoadCheckpointedSMT(bytes.NewReader(buf.Bytes()), zeroLeaf)

		b.Run(scheme.name, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				csmt.RebuildProof(3, readChunk, testHashChunk)
			}
		})
	}
}

func BenchmarkCheckpointedSaveLoad(b *testing.B) {
	data := make([]byte, 8*testChunkSize)
	if _, err := rand.Read(data); err != nil {
		b.Fatal(err)
	}
	chunks := SplitIntoChunks(data, testChunkSize)
	zeroLeaf := testZeroLeafHash()
	fullSMT, err := GenerateSparseMerkleTree(chunks, testMaxDepth, testHashChunk, zeroLeaf)
	if err != nil {
		b.Fatalf("build SMT: %v", err)
	}

	for _, scheme := range []struct {
		name string
		s    CheckpointScheme
	}{
		{"Compact", SchemeCompact},
		{"Balanced", SchemeBalanced},
		{"Fast", SchemeFast},
	} {
		b.Run(scheme.name+"/Save", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				var buf bytes.Buffer
				_ = fullSMT.SaveCheckpointed(&buf, scheme.s)
			}
		})

		var serialized bytes.Buffer
		_ = fullSMT.SaveCheckpointed(&serialized, scheme.s)
		raw := serialized.Bytes()

		b.Run(scheme.name+"/Load", func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				_, _ = LoadCheckpointedSMT(bytes.NewReader(raw), zeroLeaf)
			}
		})
	}
}

func fmtChunks(n int) string {
	return "chunks_" + itoa(n)
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	s := ""
	for n > 0 {
		s = string(rune('0'+n%10)) + s
		n /= 10
	}
	return s
}

package merkle

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

const (
	testElementSize = 31
	testChunkSize   = testElementSize * 528 // 16368 bytes ≈ 16 KB chunk
	testMaxDepth    = 20
)

// testHashChunk is a deterministic leaf hash function for testing.
func testHashChunk(chunk []byte) *big.Int {
	h := poseidon2.NewMerkleDamgardHasher()

	// Domain tag = 1 (real leaf)
	var tagFr fr.Element
	tagFr.SetInt64(1)
	tagBytes := tagFr.Bytes()
	h.Write(tagBytes[:])

	// Hash chunk elements with randomness = 1
	var oneFr fr.Element
	oneFr.SetInt64(1)

	buf := make([]byte, testElementSize)
	var elem, pre fr.Element

	for offset := 0; offset < len(chunk); offset += testElementSize {
		for i := range buf {
			buf[i] = 0
		}
		end := offset + testElementSize
		if end > len(chunk) {
			end = len(chunk)
		}
		copy(buf, chunk[offset:end])

		elem.SetBytes(buf)
		pre.Mul(&elem, &oneFr)
		preBytes := pre.Bytes()
		h.Write(preBytes[:])
	}

	// Zero-pad remaining elements
	numChunks := 528
	fed := (len(chunk) + testElementSize - 1) / testElementSize
	var zero fr.Element
	zeroBytes := zero.Bytes()
	for ; fed < numChunks; fed++ {
		h.Write(zeroBytes[:])
	}

	return new(big.Int).SetBytes(h.Sum(nil))
}

// testZeroLeafHash computes the zero leaf hash (domain tag = 0, all zeros).
func testZeroLeafHash() *big.Int {
	h := poseidon2.NewMerkleDamgardHasher()

	var tagFr fr.Element
	tagFr.SetInt64(0)
	tagBytes := tagFr.Bytes()
	h.Write(tagBytes[:])

	var zero fr.Element
	zeroBytes := zero.Bytes()
	for i := 0; i < 528; i++ {
		h.Write(zeroBytes[:])
	}

	return new(big.Int).SetBytes(h.Sum(nil))
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
			smt := GenerateSparseMerkleTree(chunks, testMaxDepth, testHashChunk, zeroLeaf)

			// Recompute root sequentially for comparison.
			seqLeafHashes := make([]*big.Int, len(chunks))
			for i, c := range chunks {
				seqLeafHashes[i] = testHashChunk(c)
			}

			// Verify leaf hashes match.
			for i, h := range seqLeafHashes {
				got := smt.GetLeafHash(i)
				if got.Cmp(h) != 0 {
					t.Fatalf("leaf %d hash mismatch: parallel=%s, sequential=%s", i, got, h)
				}
			}

			// Verify root is non-zero.
			if smt.Root.Sign() == 0 {
				t.Fatal("root hash is zero")
			}

			// Verify proof for first leaf.
			siblings, _ := smt.GetProof(0)
			if len(siblings) != testMaxDepth {
				t.Fatalf("proof length %d, want %d", len(siblings), testMaxDepth)
			}

			t.Logf("chunks=%d root=0x%x...", n, smt.Root.Bytes()[:8])
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

			original := GenerateSparseMerkleTree(chunks, testMaxDepth, testHashChunk, zeroLeaf)

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
			if loaded.Root.Cmp(original.Root) != 0 {
				t.Fatalf("root mismatch: got %s, want %s", loaded.Root, original.Root)
			}

			// Verify all level entries match.
			for lvl := 0; lvl <= original.Depth; lvl++ {
				origMap := original.Levels[lvl]
				loadMap := loaded.Levels[lvl]
				if len(origMap) != len(loadMap) {
					t.Fatalf("level %d: entry count %d != %d", lvl, len(loadMap), len(origMap))
				}
				for idx, origHash := range origMap {
					loadHash, ok := loadMap[idx]
					if !ok {
						t.Fatalf("level %d: missing index %d", lvl, idx)
					}
					if origHash.Cmp(loadHash) != 0 {
						t.Fatalf("level %d index %d: hash mismatch", lvl, idx)
					}
				}
			}

			// Verify proofs still work after load.
			for i := 0; i < n && i < 4; i++ {
				origSib, origDir := original.GetProof(i)
				loadSib, loadDir := loaded.GetProof(i)
				for j := 0; j < testMaxDepth; j++ {
					if origSib[j].Cmp(loadSib[j]) != 0 {
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
	original := GenerateSparseMerkleTree(nil, testMaxDepth, testHashChunk, zeroLeaf)

	var buf bytes.Buffer
	if err := original.Save(&buf); err != nil {
		t.Fatalf("save: %v", err)
	}

	loaded, err := LoadSparseMerkleTree(&buf, zeroLeaf)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if loaded.Root.Cmp(original.Root) != 0 {
		t.Fatalf("root mismatch for empty tree")
	}
	if loaded.NumLeaves != 0 {
		t.Fatalf("numLeaves: got %d, want 0", loaded.NumLeaves)
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
		GenerateSparseMerkleTree(chunks, testMaxDepth, testHashChunk, zeroLeaf)
	}
}

func BenchmarkSMTSaveLoad(b *testing.B) {
	data := make([]byte, 8*testChunkSize)
	if _, err := rand.Read(data); err != nil {
		b.Fatal(err)
	}
	chunks := SplitIntoChunks(data, testChunkSize)
	zeroLeaf := testZeroLeafHash()
	smt := GenerateSparseMerkleTree(chunks, testMaxDepth, testHashChunk, zeroLeaf)

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

				fullSMT := GenerateSparseMerkleTree(chunks, testMaxDepth, testHashChunk, zeroLeaf)

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
				if csmt.Root.Cmp(fullSMT.Root) != 0 {
					t.Fatalf("root mismatch")
				}

				readChunk := func(i int) []byte { return chunks[i] }

				// Test several leaf indices.
				for leafIdx := 0; leafIdx < n && leafIdx < 8; leafIdx++ {
					fullSib, fullDir := fullSMT.GetProof(leafIdx)
					result := csmt.RebuildProof(leafIdx, readChunk, testHashChunk)

					for lvl := 0; lvl < testMaxDepth; lvl++ {
						if fullSib[lvl].Cmp(result.Siblings[lvl]) != 0 {
							t.Fatalf("leaf %d: sibling mismatch at level %d: full=%s rebuilt=%s",
								leafIdx, lvl, fullSib[lvl], result.Siblings[lvl])
						}
						if fullDir[lvl] != result.Directions[lvl] {
							t.Fatalf("leaf %d: direction mismatch at level %d", leafIdx, lvl)
						}
					}

					expectedLeaf := fullSMT.GetLeafHash(leafIdx)
					if expectedLeaf.Cmp(result.LeafHash) != 0 {
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
	fullSMT := GenerateSparseMerkleTree(chunks, testMaxDepth, testHashChunk, zeroLeaf)

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
			if csmt.Root.Cmp(fullSMT.Root) != 0 {
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
					fh, ok := full[idx]
					if !ok {
						t.Fatalf("level %d index %d: not in full SMT", lvl, idx)
					}
					if sh.Cmp(fh) != 0 {
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

	fullSMT := GenerateSparseMerkleTree(chunks, testMaxDepth, testHashChunk, zeroLeaf)
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
				if fullSib[lvl].Cmp(result.Siblings[lvl]) != 0 {
					t.Fatalf("padding leaf %d: sibling mismatch at level %d", paddingIdx, lvl)
				}
				if fullDir[lvl] != result.Directions[lvl] {
					t.Fatalf("padding leaf %d: direction mismatch at level %d", paddingIdx, lvl)
				}
			}

			if result.LeafHash.Cmp(zeroLeaf) != 0 {
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

	fullSMT := GenerateSparseMerkleTree(chunks, testMaxDepth, testHashChunk, zeroLeaf)

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
			if fullSib[lvl].Cmp(result.Siblings[lvl]) != 0 {
				t.Fatalf("leaf %d: sibling mismatch at level %d", leafIdx, lvl)
			}
		}

		expectedLeaf := fullSMT.GetLeafHash(leafIdx)
		if expectedLeaf.Cmp(result.LeafHash) != 0 {
			t.Fatalf("leaf %d: leaf hash mismatch", leafIdx)
		}
	}
}

// TestCheckpointedEmpty verifies the checkpoint system handles empty trees.
func TestCheckpointedEmpty(t *testing.T) {
	zeroLeaf := testZeroLeafHash()
	fullSMT := GenerateSparseMerkleTree(nil, testMaxDepth, testHashChunk, zeroLeaf)

	var buf bytes.Buffer
	if err := fullSMT.SaveCheckpointed(&buf, SchemeBalanced); err != nil {
		t.Fatalf("save: %v", err)
	}
	csmt, err := LoadCheckpointedSMT(bytes.NewReader(buf.Bytes()), zeroLeaf)
	if err != nil {
		t.Fatalf("load: %v", err)
	}

	if csmt.Root.Cmp(fullSMT.Root) != 0 {
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
	fullSMT := GenerateSparseMerkleTree(chunks, testMaxDepth, testHashChunk, zeroLeaf)

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
	fullSMT := GenerateSparseMerkleTree(chunks, testMaxDepth, testHashChunk, zeroLeaf)

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

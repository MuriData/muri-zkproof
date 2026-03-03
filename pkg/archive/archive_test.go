package archive

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/MuriData/muri-zkproof/pkg/merkle"
	muriTransform "github.com/MuriData/muri-zkproof/pkg/muri"

	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestComputeSlotLeaf(t *testing.T) {
	m := FileMeta{
		FileRoot:         big.NewInt(42),
		NumChunks:        100,
		CumulativeChunks: 0,
	}
	h1 := ComputeSlotLeaf(m)
	h2 := ComputeSlotLeaf(m)
	if h1.Cmp(h2) != 0 {
		t.Fatal("not deterministic")
	}

	m2 := FileMeta{FileRoot: big.NewInt(42), NumChunks: 100, CumulativeChunks: 1}
	h3 := ComputeSlotLeaf(m2)
	if h1.Cmp(h3) == 0 {
		t.Fatal("collision on different cumulativeChunks")
	}
}

func TestBuildSlotTree(t *testing.T) {
	metas := []FileMeta{
		{FileRoot: big.NewInt(1), NumChunks: 10, CumulativeChunks: 0},
		{FileRoot: big.NewInt(2), NumChunks: 20, CumulativeChunks: 10},
		{FileRoot: big.NewInt(3), NumChunks: 30, CumulativeChunks: 30},
	}

	slotTree := BuildSlotTree(metas)
	if slotTree.Root.Sign() == 0 {
		t.Fatal("slot tree root is zero")
	}
	if slotTree.Depth != ArchiveIndexDepth {
		t.Fatalf("expected depth %d, got %d", ArchiveIndexDepth, slotTree.Depth)
	}
	if slotTree.NumLeaves != 3 {
		t.Fatalf("expected 3 leaves, got %d", slotTree.NumLeaves)
	}

	for i := 0; i < 3; i++ {
		siblings, directions := slotTree.GetProof(i)
		leafHash := slotTree.GetLeafHash(i)
		if !merkle.VerifySparseMerkleProof(leafHash, siblings, directions, slotTree.Root) {
			t.Fatalf("slot proof verification failed for slot %d", i)
		}
	}
}

func TestComputeArchiveOriginalRoot(t *testing.T) {
	str := big.NewInt(123)
	r1 := ComputeArchiveOriginalRoot(str, 1000)
	r2 := ComputeArchiveOriginalRoot(str, 1000)
	if r1.Cmp(r2) != 0 {
		t.Fatal("not deterministic")
	}
	r3 := ComputeArchiveOriginalRoot(str, 1001)
	if r1.Cmp(r3) == 0 {
		t.Fatal("collision on different totalRealChunks")
	}
}

func TestLogicalToPhysicalMapping(t *testing.T) {
	metas := []FileMeta{
		{FileRoot: big.NewInt(1), NumChunks: 10, CumulativeChunks: 0},
		{FileRoot: big.NewInt(2), NumChunks: 20, CumulativeChunks: 10},
	}

	mapping, err := LogicalToPhysical(5, metas)
	if err != nil {
		t.Fatal(err)
	}
	if mapping.SlotIndex != 0 || mapping.LocalChunkIndex != 5 || mapping.PhysicalPos != 5 {
		t.Fatalf("unexpected mapping: %+v", mapping)
	}

	mapping, err = LogicalToPhysical(15, metas)
	if err != nil {
		t.Fatal(err)
	}
	if mapping.SlotIndex != 1 || mapping.LocalChunkIndex != 5 {
		t.Fatalf("unexpected mapping: %+v", mapping)
	}
	expectedPhys := 1*(1<<FileTreeDepth) + 5
	if mapping.PhysicalPos != expectedPhys {
		t.Fatalf("expected physical %d, got %d", expectedPhys, mapping.PhysicalPos)
	}

	_, err = LogicalToPhysical(30, metas)
	if err == nil {
		t.Fatal("expected error for out-of-range chunk")
	}
}

func TestElementToChunk(t *testing.T) {
	chunk, offset := ElementToChunk(0)
	if chunk != 0 || offset != 0 {
		t.Fatalf("expected (0,0), got (%d,%d)", chunk, offset)
	}
	chunk, offset = ElementToChunk(529)
	if chunk != 1 || offset != 0 {
		t.Fatalf("expected (1,0), got (%d,%d)", chunk, offset)
	}
	chunk, offset = ElementToChunk(530)
	if chunk != 1 || offset != 1 {
		t.Fatalf("expected (1,1), got (%d,%d)", chunk, offset)
	}
}

func TestBuildOriginalArchiveTree(t *testing.T) {
	files := make([][]byte, 3)
	for i := range files {
		files[i] = make([]byte, FileSize*(i+1))
		rand.Read(files[i])
	}

	tree, err := BuildOriginalArchiveTree(files)
	if err != nil {
		t.Fatal(err)
	}

	if len(tree.Metas) != 3 {
		t.Fatalf("expected 3 metas, got %d", len(tree.Metas))
	}
	if tree.Metas[0].CumulativeChunks != 0 {
		t.Fatal("first meta cumulativeChunks should be 0")
	}
	if tree.Metas[1].CumulativeChunks != 1 {
		t.Fatalf("second meta cumulativeChunks should be 1, got %d", tree.Metas[1].CumulativeChunks)
	}
	if tree.Metas[2].CumulativeChunks != 3 {
		t.Fatalf("third meta cumulativeChunks should be 3, got %d", tree.Metas[2].CumulativeChunks)
	}

	// Verify depth-20 proofs against file subtree roots
	for i, ft := range tree.FileTrees {
		for c := 0; c < tree.Metas[i].NumChunks; c++ {
			siblings, directions := ft.GetProof(c)
			leafHash := ft.GetLeafHash(c)
			if !merkle.VerifySparseMerkleProof(leafHash, siblings, directions, ft.Root) {
				t.Fatalf("file %d, chunk %d: depth-20 proof failed", i, c)
			}
		}
	}

	// Verify depth-10 slot proofs
	for i := range tree.Metas {
		siblings, directions := tree.SlotTree.GetProof(i)
		leafHash := tree.SlotTree.GetLeafHash(i)
		if !merkle.VerifySparseMerkleProof(leafHash, siblings, directions, tree.SlotTree.Root) {
			t.Fatalf("slot %d: depth-10 proof failed", i)
		}
	}
}

func TestReplicaDepth30Proof(t *testing.T) {
	// Create 2 files, seal them, build replica tree, verify depth-30 proofs.
	files := [][]byte{
		make([]byte, 2*FileSize),
		make([]byte, 3*FileSize),
	}
	rand.Read(files[0])
	rand.Read(files[1])

	origTree, err := BuildOriginalArchiveTree(files)
	if err != nil {
		t.Fatal(err)
	}

	// Convert file data to flat field elements for sealing
	totalChunks := TotalRealChunks(origTree.Metas)
	allChunks := make([][]byte, 0, totalChunks)
	for _, data := range files {
		chunks := merkle.SplitIntoChunks(data, FileSize)
		allChunks = append(allChunks, chunks...)
	}

	origElements := chunksToElements(allChunks)
	r := big.NewInt(42)
	sealResult := muriTransform.SealArchive(origElements, r)

	replicaTree, err := BuildReplicaArchiveTree(sealResult.Enc2, origTree.Metas)
	if err != nil {
		t.Fatal(err)
	}

	// Verify depth-30 proofs against replica root
	for logChunk := 0; logChunk < totalChunks; logChunk++ {
		mapping, err := LogicalToPhysical(logChunk, origTree.Metas)
		if err != nil {
			t.Fatal(err)
		}

		siblings, directions := replicaTree.GetDepth30Proof(mapping.PhysicalPos)
		if len(siblings) != ArchiveTreeDepth {
			t.Fatalf("expected %d siblings, got %d", ArchiveTreeDepth, len(siblings))
		}

		leafHash := replicaTree.GetLeafHash(mapping.PhysicalPos)
		if !merkle.VerifySparseMerkleProof(leafHash, siblings, directions, replicaTree.Root()) {
			t.Fatalf("depth-30 proof failed for logical chunk %d (physical %d)", logChunk, mapping.PhysicalPos)
		}
	}
}

func TestTotalRealChunks(t *testing.T) {
	metas := []FileMeta{
		{NumChunks: 10, CumulativeChunks: 0},
		{NumChunks: 20, CumulativeChunks: 10},
		{NumChunks: 5, CumulativeChunks: 30},
	}
	if got := TotalRealChunks(metas); got != 35 {
		t.Fatalf("expected 35, got %d", got)
	}
	if got := TotalRealChunks(nil); got != 0 {
		t.Fatalf("expected 0 for nil, got %d", got)
	}
}

// chunksToElements converts raw chunk bytes to flat fr.Element array.
func chunksToElements(chunks [][]byte) []fr.Element {
	totalElements := len(chunks) * ElementsPerChunk
	elements := make([]fr.Element, totalElements)
	for c, chunk := range chunks {
		for e := 0; e < ElementsPerChunk; e++ {
			start := e * ElementSize
			end := start + ElementSize
			if end > len(chunk) {
				end = len(chunk)
			}
			if start < len(chunk) {
				buf := make([]byte, ElementSize)
				copy(buf, chunk[start:end])
				elements[c*ElementsPerChunk+e].SetBytes(buf)
			}
		}
	}
	return elements
}

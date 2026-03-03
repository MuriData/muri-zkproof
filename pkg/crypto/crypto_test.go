package crypto

import (
	"math/big"
	"testing"
)

func TestDomainTagsAreDistinct(t *testing.T) {
	tags := map[int]string{
		DomainTagPadding:      "Padding",
		DomainTagReal:         "Real",
		DomainTagNode:         "Node",
		DomainTagSlot:         "Slot",
		DomainTagGlobalR:      "GlobalR",
		DomainTagKeySeed1:     "KeySeed1",
		DomainTagKeyElem1:     "KeyElem1",
		DomainTagPubKey:       "PubKey",
		DomainTagAggMsg:       "AggMsg",
		DomainTagCommitment:   "Commitment",
		DomainTagChallengeIdx: "ChallengeIdx",
		DomainTagKeySeed2:     "KeySeed2",
		DomainTagKeyElem2:     "KeyElem2",
		DomainTagArchiveRoot:  "ArchiveRoot",
		DomainTagBackPtr1:     "BackPtr1",
		DomainTagBackPtr2:     "BackPtr2",
	}
	if len(tags) != 16 {
		t.Fatalf("expected 16 distinct domain tags, got %d", len(tags))
	}
}

func TestHashSlotLeafDeterministic(t *testing.T) {
	root := big.NewInt(42)
	h1 := HashSlotLeaf(root, 100, 0)
	h2 := HashSlotLeaf(root, 100, 0)
	if h1.Cmp(h2) != 0 {
		t.Fatal("HashSlotLeaf not deterministic")
	}
	// Different inputs produce different outputs.
	h3 := HashSlotLeaf(root, 100, 1)
	if h1.Cmp(h3) == 0 {
		t.Fatal("HashSlotLeaf collision on different cumulativeChunks")
	}
}

func TestDeriveGlobalRDeterministic(t *testing.T) {
	pk := big.NewInt(999)
	aor := big.NewInt(888)
	r1 := DeriveGlobalR(pk, aor)
	r2 := DeriveGlobalR(pk, aor)
	if r1.Cmp(r2) != 0 {
		t.Fatal("DeriveGlobalR not deterministic")
	}
	if r1.Sign() == 0 {
		t.Fatal("DeriveGlobalR returned zero")
	}
}

func TestDeriveArchiveOriginalRoot(t *testing.T) {
	str := big.NewInt(123)
	h1 := DeriveArchiveOriginalRoot(str, 1000)
	h2 := DeriveArchiveOriginalRoot(str, 1000)
	if h1.Cmp(h2) != 0 {
		t.Fatal("not deterministic")
	}
	h3 := DeriveArchiveOriginalRoot(str, 1001)
	if h1.Cmp(h3) == 0 {
		t.Fatal("collision on different totalRealChunks")
	}
}

func TestDeriveKeySeedsDomainSeparation(t *testing.T) {
	r := big.NewInt(77)
	s1 := DeriveKeySeed1(r)
	s2 := DeriveKeySeed2(r)
	if s1.Cmp(s2) == 0 {
		t.Fatal("KeySeed1 and KeySeed2 collide for same r")
	}
}

func TestDeriveBackPointers(t *testing.T) {
	r := big.NewInt(12345)

	// Pass 1: j=10, distance=10, k=5, bitsPerBP=50
	bp1 := DeriveBackPointers(10, r, DomainTagBackPtr1, 10, 5, 50)
	if len(bp1) != 5 {
		t.Fatalf("expected 5 back-pointers, got %d", len(bp1))
	}
	for i, pos := range bp1 {
		if pos < 0 || pos >= 10 {
			t.Fatalf("bp1[%d] = %d out of range [0, 10)", i, pos)
		}
	}

	// Pass 2: j=5, N=100, distance=94, k=5, bitsPerBP=50
	// Results should be in (5, 99] = [6, 99]
	bp2 := DeriveBackPointers(5, r, DomainTagBackPtr2, 94, 5, 50)
	if len(bp2) != 5 {
		t.Fatalf("expected 5 back-pointers, got %d", len(bp2))
	}
	for i, pos := range bp2 {
		if pos < 6 || pos > 99 {
			t.Fatalf("bp2[%d] = %d out of range [6, 99]", i, pos)
		}
	}

	// Deterministic
	bp1b := DeriveBackPointers(10, r, DomainTagBackPtr1, 10, 5, 50)
	for i := range bp1 {
		if bp1[i] != bp1b[i] {
			t.Fatalf("bp1[%d] not deterministic: %d vs %d", i, bp1[i], bp1b[i])
		}
	}

	// Domain separation: same j, r but different pass tag
	bp1c := DeriveBackPointers(10, r, DomainTagBackPtr1, 10, 5, 50)
	bp2c := DeriveBackPointers(10, r, DomainTagBackPtr2, 10, 5, 50)
	// bp2c positions are offset: j+1+raw, so they should differ from bp1c
	same := true
	for i := range bp1c {
		if bp1c[i] != bp2c[i] {
			same = false
			break
		}
	}
	if same {
		t.Fatal("Pass 1 and Pass 2 back-pointers identical despite different tags")
	}
}

func TestDeriveBackPointersEdgeCaseZeroDistance(t *testing.T) {
	r := big.NewInt(42)
	bp := DeriveBackPointers(0, r, DomainTagBackPtr1, 0, 5, 50)
	for i, pos := range bp {
		if pos != 0 {
			t.Fatalf("expected 0 for zero distance, got bp[%d]=%d", i, pos)
		}
	}
}

func TestDeriveKeyElems(t *testing.T) {
	prev := big.NewInt(100)
	bps := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)}
	r := big.NewInt(42)

	k1 := DeriveKeyElem1(prev, bps, r)
	if k1.Sign() == 0 {
		t.Fatal("DeriveKeyElem1 returned zero")
	}

	k2 := DeriveKeyElem2(prev, bps, r)
	if k2.Sign() == 0 {
		t.Fatal("DeriveKeyElem2 returned zero")
	}

	// Domain separation
	if k1.Cmp(k2) == 0 {
		t.Fatal("KeyElem1 and KeyElem2 collide")
	}
}

func TestDeriveChallengeIdx(t *testing.T) {
	cr := big.NewInt(999)
	h1 := DeriveChallengeIdx(cr, 0)
	h2 := DeriveChallengeIdx(cr, 1)
	if h1.Cmp(h2) == 0 {
		t.Fatal("same output for different seeds")
	}
	h3 := DeriveChallengeIdx(cr, 0)
	if h1.Cmp(h3) != 0 {
		t.Fatal("not deterministic")
	}
}

func TestFieldModulus(t *testing.T) {
	m := FieldModulus()
	if m.Sign() == 0 {
		t.Fatal("field modulus is zero")
	}
	if m.BitLen() != 254 {
		t.Fatalf("expected 254-bit modulus, got %d", m.BitLen())
	}
}

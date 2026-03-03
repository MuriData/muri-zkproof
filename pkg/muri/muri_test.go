package muri

import (
	"math/big"
	"testing"

	"github.com/MuriData/muri-zkproof/pkg/crypto"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func TestSealUnsealRoundTrip(t *testing.T) {
	// Create a small test archive: 3 chunks × 529 elements = 1587 elements.
	N := 3 * ElementsPerChunk
	orig := make([]fr.Element, N)
	for i := 0; i < N; i++ {
		orig[i].SetInt64(int64(i + 1))
	}

	r := big.NewInt(42)

	result := SealArchive(orig, r)
	if len(result.Enc1) != N {
		t.Fatalf("enc1 length %d, expected %d", len(result.Enc1), N)
	}
	if len(result.Enc2) != N {
		t.Fatalf("enc2 length %d, expected %d", len(result.Enc2), N)
	}

	// enc2 should differ from orig (encryption actually happened)
	allSame := true
	for i := 0; i < N; i++ {
		if !orig[i].Equal(&result.Enc2[i]) {
			allSame = false
			break
		}
	}
	if allSame {
		t.Fatal("enc2 is identical to orig — encryption did nothing")
	}

	// Unseal and verify round-trip
	recovered := UnsealArchive(result.Enc2, r)
	if len(recovered) != N {
		t.Fatalf("recovered length %d, expected %d", len(recovered), N)
	}
	for i := 0; i < N; i++ {
		if !orig[i].Equal(&recovered[i]) {
			var origBig, recBig big.Int
			orig[i].BigInt(&origBig)
			recovered[i].BigInt(&recBig)
			t.Fatalf("mismatch at element %d: orig=%s, recovered=%s", i, origBig.String(), recBig.String())
		}
	}
}

func TestSealUnsealSingleElement(t *testing.T) {
	// Edge case: single element
	orig := []fr.Element{{}}
	orig[0].SetInt64(42)
	r := big.NewInt(7)

	result := SealArchive(orig, r)
	recovered := UnsealArchive(result.Enc2, r)
	if !orig[0].Equal(&recovered[0]) {
		t.Fatal("single element round-trip failed")
	}
}

func TestPartialUnseal(t *testing.T) {
	N := 2 * ElementsPerChunk
	orig := make([]fr.Element, N)
	for i := 0; i < N; i++ {
		orig[i].SetInt64(int64(i + 100))
	}

	r := big.NewInt(999)
	result := SealArchive(orig, r)

	// Unseal just the second chunk
	start := ElementsPerChunk
	end := 2 * ElementsPerChunk
	partial := UnsealElements(result.Enc2, r, start, end)
	if len(partial) != ElementsPerChunk {
		t.Fatalf("partial length %d, expected %d", len(partial), ElementsPerChunk)
	}
	for i := 0; i < ElementsPerChunk; i++ {
		if !orig[start+i].Equal(&partial[i]) {
			t.Fatalf("partial unseal mismatch at offset %d", i)
		}
	}
}

func TestSealDeterministic(t *testing.T) {
	N := ElementsPerChunk
	orig := make([]fr.Element, N)
	for i := 0; i < N; i++ {
		orig[i].SetInt64(int64(i))
	}
	r := big.NewInt(123)

	r1 := SealArchive(orig, r)
	r2 := SealArchive(orig, r)
	for i := 0; i < N; i++ {
		if !r1.Enc2[i].Equal(&r2.Enc2[i]) {
			t.Fatalf("sealing not deterministic at element %d", i)
		}
	}
}

func TestSealDifferentR(t *testing.T) {
	N := ElementsPerChunk
	orig := make([]fr.Element, N)
	for i := 0; i < N; i++ {
		orig[i].SetInt64(int64(i + 1))
	}

	r1Result := SealArchive(orig, big.NewInt(1))
	r2Result := SealArchive(orig, big.NewInt(2))

	same := true
	for i := 0; i < N; i++ {
		if !r1Result.Enc2[i].Equal(&r2Result.Enc2[i]) {
			same = false
			break
		}
	}
	if same {
		t.Fatal("different r produced identical enc2")
	}
}

func TestBackPointerRanges(t *testing.T) {
	// Verify back-pointer positions are in the correct range
	r := big.NewInt(42)
	N := 100

	for j := 1; j < N; j++ {
		bp1 := crypto.DeriveBackPointers(j, r, crypto.DomainTagBackPtr1, j, BackPointers, BitsPerBP)
		for m, pos := range bp1 {
			if pos < 0 || pos >= j {
				t.Fatalf("Pass 1 bp[%d] for j=%d out of range: %d not in [0,%d)", m, j, pos, j)
			}
		}
	}

	for j := 0; j < N-1; j++ {
		distance := N - 1 - j
		bp2 := crypto.DeriveBackPointers(j, r, crypto.DomainTagBackPtr2, distance, BackPointers, BitsPerBP)
		for m, pos := range bp2 {
			if pos <= j || pos >= N {
				t.Fatalf("Pass 2 bp[%d] for j=%d out of range: %d not in (%d,%d]", m, j, pos, j, N-1)
			}
		}
	}
}

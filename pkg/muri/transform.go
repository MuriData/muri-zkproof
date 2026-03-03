package muri

import (
	"math/big"

	"github.com/MuriData/muri-zkproof/pkg/crypto"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// SealResult holds the output of the two-pass sealing transform.
type SealResult struct {
	Enc1 []fr.Element // Intermediate Pass 1 output (discarded after Pass 2 in production)
	Enc2 []fr.Element // Final encrypted elements (stored as replica)
}

// SealArchive applies the two-pass sequential MURI transform (MURI.md Section 5).
// origElements are the original field elements in flat logical order.
// r is the global randomness derived from H(DomainTagGlobalR, publicKey, archiveOriginalRoot).
// Returns both enc1 (for testing) and enc2 (the stored replica).
func SealArchive(origElements []fr.Element, r *big.Int) *SealResult {
	N := len(origElements)
	if N == 0 {
		return &SealResult{}
	}

	enc1 := make([]fr.Element, N)
	enc2 := make([]fr.Element, N)

	// ---------------------------------------------------------------
	// Pass 1: Left-to-Right
	// ---------------------------------------------------------------
	// Element 0: key1[0] = H(DomainTagKeySeed1, r)
	key1Seed := crypto.DeriveKeySeed1(r)
	var key1Fr fr.Element
	key1Fr.SetBigInt(key1Seed)
	enc1[0].Add(&origElements[0], &key1Fr)

	// Elements 1..N-1
	for j := 1; j < N; j++ {
		bp1 := crypto.DeriveBackPointers(j, r, crypto.DomainTagBackPtr1, j, BackPointers, BitsPerBP)
		enc1BPs := make([]*big.Int, BackPointers)
		for m := 0; m < BackPointers; m++ {
			enc1BPs[m] = frToBig(&enc1[bp1[m]])
		}
		key1Big := crypto.DeriveKeyElem1(frToBig(&enc1[j-1]), enc1BPs, r)
		key1Fr.SetBigInt(key1Big)
		enc1[j].Add(&origElements[j], &key1Fr)
	}

	// ---------------------------------------------------------------
	// Pass 2: Right-to-Left
	// ---------------------------------------------------------------
	// Element N-1: key2[N-1] = H(DomainTagKeySeed2, r)
	key2Seed := crypto.DeriveKeySeed2(r)
	var key2Fr fr.Element
	key2Fr.SetBigInt(key2Seed)
	enc2[N-1].Add(&enc1[N-1], &key2Fr)

	// Elements N-2..0
	for j := N - 2; j >= 0; j-- {
		bp2 := crypto.DeriveBackPointers(j, r, crypto.DomainTagBackPtr2, N-1-j, BackPointers, BitsPerBP)
		enc2BPs := make([]*big.Int, BackPointers)
		for m := 0; m < BackPointers; m++ {
			enc2BPs[m] = frToBig(&enc2[bp2[m]])
		}
		key2Big := crypto.DeriveKeyElem2(frToBig(&enc2[j+1]), enc2BPs, r)
		key2Fr.SetBigInt(key2Big)
		enc2[j].Add(&enc1[j], &key2Fr)
	}

	return &SealResult{Enc1: enc1, Enc2: enc2}
}

// frToBig converts an fr.Element to *big.Int.
func frToBig(e *fr.Element) *big.Int {
	b := new(big.Int)
	e.BigInt(b)
	return b
}

// BigToFr converts *big.Int to fr.Element.
func BigToFr(b *big.Int) fr.Element {
	var e fr.Element
	e.SetBigInt(b)
	return e
}

package muri

import (
	"math/big"
	"runtime"
	"sync"

	"github.com/MuriData/muri-zkproof/pkg/crypto"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// UnsealArchive reverses the two-pass MURI transform to recover original elements.
// Pass 2 reversal (L→R) and Pass 1 reversal (L→R) are both sequential.
func UnsealArchive(enc2 []fr.Element, r *big.Int) []fr.Element {
	N := len(enc2)
	if N == 0 {
		return nil
	}

	enc1 := make([]fr.Element, N)
	orig := make([]fr.Element, N)

	// ---------------------------------------------------------------
	// Reverse Pass 2: recover enc1 from enc2, right-to-left chain reversed.
	// enc1[j] = enc2[j] - key2[j]
	// Process left-to-right for N-1 first (seed key), then N-2..0 need
	// enc2[j+1] which is already available.
	// Actually, we reverse in the same R→L order: start at N-1, go to 0.
	// ---------------------------------------------------------------

	// Element N-1: key2 = seed key
	key2Seed := crypto.DeriveKeySeed2(r)
	var key2Fr fr.Element
	key2Fr.SetBigInt(key2Seed)
	enc1[N-1].Sub(&enc2[N-1], &key2Fr)

	// Elements N-2..0: key2[j] depends on enc2[j+1] and enc2[bp2[...]]
	// All enc2 values are available, so we can go in any order.
	// But enc1 values are not needed for key2, so this is parallelizable.
	// For simplicity and correctness, do it sequentially (order doesn't matter
	// since key2[j] only depends on enc2 which is fully available).
	numWorkers := runtime.NumCPU()
	if numWorkers > N {
		numWorkers = N
	}
	if N > 1 {
		var wg sync.WaitGroup
		work := make(chan int, N-1)
		for w := 0; w < numWorkers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				var kFr fr.Element
				for j := range work {
					bp2 := crypto.DeriveBackPointers(j, r, crypto.DomainTagBackPtr2, N-1-j, BackPointers, BitsPerBP)
					enc2BPs := make([]*big.Int, BackPointers)
					for m := 0; m < BackPointers; m++ {
						enc2BPs[m] = frToBig(&enc2[bp2[m]])
					}
					key2Big := crypto.DeriveKeyElem2(frToBig(&enc2[j+1]), enc2BPs, r)
					kFr.SetBigInt(key2Big)
					enc1[j].Sub(&enc2[j], &kFr)
				}
			}()
		}
		for j := N - 2; j >= 0; j-- {
			work <- j
		}
		close(work)
		wg.Wait()
	}

	// ---------------------------------------------------------------
	// Reverse Pass 1: recover orig from enc1, left-to-right chain.
	// orig[j] = enc1[j] - key1[j]
	// key1[0] = seed key; key1[j] depends on enc1[j-1] and enc1[bp1[...]]
	// All enc1 values are now available, so this is also parallelizable.
	// ---------------------------------------------------------------

	// Element 0: seed key
	key1Seed := crypto.DeriveKeySeed1(r)
	var key1Fr fr.Element
	key1Fr.SetBigInt(key1Seed)
	orig[0].Sub(&enc1[0], &key1Fr)

	if N > 1 {
		var wg sync.WaitGroup
		work := make(chan int, N-1)
		for w := 0; w < numWorkers; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				var kFr fr.Element
				for j := range work {
					bp1 := crypto.DeriveBackPointers(j, r, crypto.DomainTagBackPtr1, j, BackPointers, BitsPerBP)
					enc1BPs := make([]*big.Int, BackPointers)
					for m := 0; m < BackPointers; m++ {
						enc1BPs[m] = frToBig(&enc1[bp1[m]])
					}
					key1Big := crypto.DeriveKeyElem1(frToBig(&enc1[j-1]), enc1BPs, r)
					kFr.SetBigInt(key1Big)
					orig[j].Sub(&enc1[j], &kFr)
				}
			}()
		}
		for j := 1; j < N; j++ {
			work <- j
		}
		close(work)
		wg.Wait()
	}

	return orig
}

// UnsealElements reverses the MURI transform for a range of elements [startElem, endElem).
// Useful for extracting a single file from an archive without unsealing the entire archive.
// enc2 must be the complete enc2 array (all elements needed for back-pointer lookups).
func UnsealElements(enc2 []fr.Element, r *big.Int, startElem, endElem int) []fr.Element {
	N := len(enc2)
	if N == 0 || startElem >= endElem || startElem >= N {
		return nil
	}
	if endElem > N {
		endElem = N
	}

	result := make([]fr.Element, endElem-startElem)

	for j := startElem; j < endElem; j++ {
		// Reverse Pass 2: enc1[j] = enc2[j] - key2[j]
		var enc1j fr.Element
		if j == N-1 {
			key2Seed := crypto.DeriveKeySeed2(r)
			var kFr fr.Element
			kFr.SetBigInt(key2Seed)
			enc1j.Sub(&enc2[j], &kFr)
		} else {
			bp2 := crypto.DeriveBackPointers(j, r, crypto.DomainTagBackPtr2, N-1-j, BackPointers, BitsPerBP)
			enc2BPs := make([]*big.Int, BackPointers)
			for m := 0; m < BackPointers; m++ {
				enc2BPs[m] = frToBig(&enc2[bp2[m]])
			}
			key2Big := crypto.DeriveKeyElem2(frToBig(&enc2[j+1]), enc2BPs, r)
			var kFr fr.Element
			kFr.SetBigInt(key2Big)
			enc1j.Sub(&enc2[j], &kFr)
		}

		// Reverse Pass 1: orig[j] = enc1[j] - key1[j]
		// key1[j] depends on enc1[j-1] and enc1[bp1[...]].
		// We need to derive enc1 for those positions too.
		var origj fr.Element
		if j == 0 {
			key1Seed := crypto.DeriveKeySeed1(r)
			var kFr fr.Element
			kFr.SetBigInt(key1Seed)
			origj.Sub(&enc1j, &kFr)
		} else {
			// Derive enc1 for predecessor and back-pointers
			enc1Prev := deriveEnc1(enc2, r, j-1, N)
			bp1 := crypto.DeriveBackPointers(j, r, crypto.DomainTagBackPtr1, j, BackPointers, BitsPerBP)
			enc1BPs := make([]*big.Int, BackPointers)
			for m := 0; m < BackPointers; m++ {
				enc1BPs[m] = deriveEnc1Big(enc2, r, bp1[m], N)
			}
			key1Big := crypto.DeriveKeyElem1(frToBig(&enc1Prev), enc1BPs, r)
			var kFr fr.Element
			kFr.SetBigInt(key1Big)
			origj.Sub(&enc1j, &kFr)
		}

		result[j-startElem] = origj
	}

	return result
}

// deriveEnc1 recovers enc1[j] = enc2[j] - key2[j] from enc2.
func deriveEnc1(enc2 []fr.Element, r *big.Int, j, N int) fr.Element {
	var enc1j, kFr fr.Element
	if j == N-1 {
		kFr.SetBigInt(crypto.DeriveKeySeed2(r))
	} else {
		bp2 := crypto.DeriveBackPointers(j, r, crypto.DomainTagBackPtr2, N-1-j, BackPointers, BitsPerBP)
		enc2BPs := make([]*big.Int, BackPointers)
		for m := 0; m < BackPointers; m++ {
			enc2BPs[m] = frToBig(&enc2[bp2[m]])
		}
		kFr.SetBigInt(crypto.DeriveKeyElem2(frToBig(&enc2[j+1]), enc2BPs, r))
	}
	enc1j.Sub(&enc2[j], &kFr)
	return enc1j
}

// deriveEnc1Big returns enc1[j] as *big.Int.
func deriveEnc1Big(enc2 []fr.Element, r *big.Int, j, N int) *big.Int {
	e := deriveEnc1(enc2, r, j, N)
	return frToBig(&e)
}

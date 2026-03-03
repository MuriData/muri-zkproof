package crypto

import (
	"crypto/rand"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
)

// Domain separation tags for all Poseidon2 invocations (MURI.md Section 2.4).
const (
	DomainTagPadding      = 0
	DomainTagReal         = 1
	DomainTagNode         = 2
	DomainTagSlot         = 3
	DomainTagGlobalR      = 4
	DomainTagKeySeed1     = 5
	DomainTagKeyElem1     = 6
	DomainTagPubKey       = 7
	DomainTagAggMsg       = 8
	DomainTagCommitment   = 9
	DomainTagChallengeIdx = 10
	DomainTagKeySeed2     = 11
	DomainTagKeyElem2     = 12
	DomainTagArchiveRoot  = 13
	DomainTagBackPtr1     = 14
	DomainTagBackPtr2     = 15
)

// Hash hashes the data using the Poseidon2 hash function and the given randomness.
// elementSize is the byte width of each field element.
// numChunks is the total number of chunks (data is padded with zeros to this count).
func Hash(data []byte, randomness *big.Int, elementSize, numChunks int) *big.Int {
	h := poseidon2.NewMerkleDamgardHasher()

	// randomness as field element (only once)
	var randElement fr.Element
	randElement.SetBigInt(randomness)

	buf := make([]byte, elementSize)
	var element, preImageElement fr.Element

	for offset := 0; offset < len(data); offset += elementSize {
		// Zero the buffer without reallocating.
		for i := range buf {
			buf[i] = 0
		}

		end := offset + elementSize
		if end > len(data) {
			end = len(data)
		}
		copy(buf, data[offset:end])

		// element = buf * randomness (field multiplication)
		element.SetBytes(buf)
		preImageElement.Mul(&element, &randElement)

		preBytes := preImageElement.Bytes()
		h.Write(preBytes[:])
	}

	// Remaining zero chunks (0 * randomness = 0)
	var zero fr.Element // already zero
	zeroBytes := zero.Bytes()
	fed := (len(data) + elementSize - 1) / elementSize
	for ; fed < numChunks; fed++ {
		h.Write(zeroBytes[:])
	}

	return new(big.Int).SetBytes(h.Sum(nil))
}

// HashWithDomainTag hashes data with a domain separation tag prepended as the
// first Poseidon2 input element. Otherwise identical to Hash: each data element
// is multiplied by randomness, then zero-padded to numChunks total elements.
// The total number of Poseidon2 writes is 1 (tag) + numChunks.
func HashWithDomainTag(tag int, data []byte, randomness *big.Int, elementSize, numChunks int) *big.Int {
	h := poseidon2.NewMerkleDamgardHasher()

	// Write domain tag as the first element.
	var tagFr fr.Element
	tagFr.SetInt64(int64(tag))
	tagBytes := tagFr.Bytes()
	h.Write(tagBytes[:])

	// randomness as field element (only once)
	var randElement fr.Element
	randElement.SetBigInt(randomness)

	buf := make([]byte, elementSize)
	var element, preImageElement fr.Element

	for offset := 0; offset < len(data); offset += elementSize {
		for i := range buf {
			buf[i] = 0
		}

		end := offset + elementSize
		if end > len(data) {
			end = len(data)
		}
		copy(buf, data[offset:end])

		element.SetBytes(buf)
		preImageElement.Mul(&element, &randElement)

		preBytes := preImageElement.Bytes()
		h.Write(preBytes[:])
	}

	// Remaining zero chunks (0 * randomness = 0)
	var zero fr.Element
	zeroBytes := zero.Bytes()
	fed := (len(data) + elementSize - 1) / elementSize
	if len(data) == 0 {
		fed = 0
	}
	for ; fed < numChunks; fed++ {
		h.Write(zeroBytes[:])
	}

	return new(big.Int).SetBytes(h.Sum(nil))
}

// ComputeZeroLeafHash returns the hash of a padding (empty) leaf with
// DomainTagPadding. This is: H(0, 0, 0, ..., 0) with 1 + numChunks elements.
func ComputeZeroLeafHash(elementSize, numChunks int) *big.Int {
	return HashWithDomainTag(DomainTagPadding, []byte{}, big.NewInt(1), elementSize, numChunks)
}

// GenerateSecretKey generates a random secret key as a non-zero BN254 scalar field element.
func GenerateSecretKey() (*big.Int, error) {
	for {
		sk, err := rand.Int(rand.Reader, ecc.BN254.ScalarField())
		if err != nil {
			return nil, err
		}
		if sk.Sign() != 0 {
			return sk, nil
		}
	}
}

// DerivePublicKey computes publicKey = H(secretKey) using Poseidon2, matching the circuit.
func DerivePublicKey(secretKey *big.Int) *big.Int {
	h := poseidon2.NewMerkleDamgardHasher()

	var skFr fr.Element
	skFr.SetBigInt(secretKey)
	skBytes := skFr.Bytes()
	h.Write(skBytes[:])

	return new(big.Int).SetBytes(h.Sum(nil))
}

// DeriveAggMsg computes the aggregate message from multiple leaf hashes and
// randomness: aggMsg = H(leafHash[0], ..., leafHash[n-1], randomness).
// This matches the multi-opening circuit's aggregate message computation.
func DeriveAggMsg(leafHashes []*big.Int, randomness *big.Int) *big.Int {
	h := poseidon2.NewMerkleDamgardHasher()

	for _, lh := range leafHashes {
		var elem fr.Element
		elem.SetBigInt(lh)
		b := elem.Bytes()
		h.Write(b[:])
	}

	var randFr fr.Element
	randFr.SetBigInt(randomness)
	randBytes := randFr.Bytes()
	h.Write(randBytes[:])

	return new(big.Int).SetBytes(h.Sum(nil))
}

// DeriveCommitment computes the VRF-style commitment matching the circuit:
// commitment = H(secretKey, msg, randomness, publicKey)
func DeriveCommitment(secretKey, msg, randomness, publicKey *big.Int) *big.Int {
	h := poseidon2.NewMerkleDamgardHasher()

	var skFr, msgFr, randFr, pkFr fr.Element
	skFr.SetBigInt(secretKey)
	msgFr.SetBigInt(msg)
	randFr.SetBigInt(randomness)
	pkFr.SetBigInt(publicKey)

	skBytes := skFr.Bytes()
	msgBytes := msgFr.Bytes()
	randBytes := randFr.Bytes()
	pkBytes := pkFr.Bytes()

	h.Write(skBytes[:])
	h.Write(msgBytes[:])
	h.Write(randBytes[:])
	h.Write(pkBytes[:])

	return new(big.Int).SetBytes(h.Sum(nil))
}

// ---------------------------------------------------------------------------
// Archive / MURI crypto primitives (MURI.md Sections 2.4, 3, 5)
// ---------------------------------------------------------------------------

// hashFieldElements is a helper that hashes a domain tag followed by field elements.
func hashFieldElements(tag int, elems ...*big.Int) *big.Int {
	h := poseidon2.NewMerkleDamgardHasher()
	var tmp fr.Element
	tmp.SetInt64(int64(tag))
	b := tmp.Bytes()
	h.Write(b[:])
	for _, e := range elems {
		tmp.SetBigInt(e)
		b = tmp.Bytes()
		h.Write(b[:])
	}
	return new(big.Int).SetBytes(h.Sum(nil))
}

// HashSlotLeaf computes slotLeaf = H(DomainTagSlot, fileRoot, numChunks, cumulativeChunks).
func HashSlotLeaf(fileRoot *big.Int, numChunks, cumulativeChunks int) *big.Int {
	return hashFieldElements(DomainTagSlot, fileRoot, big.NewInt(int64(numChunks)), big.NewInt(int64(cumulativeChunks)))
}

// DeriveGlobalR computes r = H(DomainTagGlobalR, publicKey, archiveOriginalRoot).
func DeriveGlobalR(publicKey, archiveOriginalRoot *big.Int) *big.Int {
	return hashFieldElements(DomainTagGlobalR, publicKey, archiveOriginalRoot)
}

// DeriveArchiveOriginalRoot computes H(DomainTagArchiveRoot, slotTreeRoot, totalRealChunks).
func DeriveArchiveOriginalRoot(slotTreeRoot *big.Int, totalRealChunks int) *big.Int {
	return hashFieldElements(DomainTagArchiveRoot, slotTreeRoot, big.NewInt(int64(totalRealChunks)))
}

// DeriveKeySeed1 computes key1[0] = H(DomainTagKeySeed1, r).
func DeriveKeySeed1(r *big.Int) *big.Int {
	return hashFieldElements(DomainTagKeySeed1, r)
}

// DeriveKeySeed2 computes key2[N-1] = H(DomainTagKeySeed2, r).
func DeriveKeySeed2(r *big.Int) *big.Int {
	return hashFieldElements(DomainTagKeySeed2, r)
}

// DeriveBackPointerSeed computes seed = H(domainTag, j, r).
func DeriveBackPointerSeed(domainTag int, j int, r *big.Int) *big.Int {
	return hashFieldElements(domainTag, big.NewInt(int64(j)), r)
}

// DeriveBackPointers computes k back-pointer positions for element j.
// For Pass 1 (DomainTagBackPtr1): distance = j, positions in [0, j).
// For Pass 2 (DomainTagBackPtr2): distance = N-1-j, raw positions mod distance,
// then offset to (j, N-1] as j + 1 + bp[m].
// bitsPerBP is typically 50. k is the number of back-pointers.
func DeriveBackPointers(j int, r *big.Int, domainTag int, distance int, k int, bitsPerBP int) []int {
	if distance == 0 {
		// Edge case: no back-pointers possible (j==0 for Pass 1, j==N-1 for Pass 2).
		bp := make([]int, k)
		return bp
	}

	seed := DeriveBackPointerSeed(domainTag, j, r)
	seedBig := new(big.Int).Set(seed)

	bp := make([]int, k)
	distBig := big.NewInt(int64(distance))
	for m := 0; m < k; m++ {
		// Extract bitsPerBP bits starting at m*bitsPerBP.
		var rawVal big.Int
		for b := 0; b < bitsPerBP; b++ {
			if seedBig.Bit(m*bitsPerBP+b) != 0 {
				rawVal.SetBit(&rawVal, b, 1)
			}
		}
		rawVal.Mod(&rawVal, distBig)
		bp[m] = int(rawVal.Int64())
	}

	// For Pass 2, offset to (j, N-1]: bp[m] = j + 1 + bp[m]
	if domainTag == DomainTagBackPtr2 {
		for m := 0; m < k; m++ {
			bp[m] = j + 1 + bp[m]
		}
	}

	return bp
}

// DeriveKeyElem1 computes key1[j] = H(DomainTagKeyElem1, enc1[j-1], enc1[bp1[0]], ..., enc1[bp1[k-1]], r).
func DeriveKeyElem1(enc1Prev *big.Int, enc1BPs []*big.Int, r *big.Int) *big.Int {
	elems := make([]*big.Int, 0, 2+len(enc1BPs))
	elems = append(elems, enc1Prev)
	elems = append(elems, enc1BPs...)
	elems = append(elems, r)
	return hashFieldElements(DomainTagKeyElem1, elems...)
}

// DeriveKeyElem2 computes key2[j] = H(DomainTagKeyElem2, enc2[j+1], enc2[bp2[0]], ..., enc2[bp2[k-1]], r).
func DeriveKeyElem2(enc2Next *big.Int, enc2BPs []*big.Int, r *big.Int) *big.Int {
	elems := make([]*big.Int, 0, 2+len(enc2BPs))
	elems = append(elems, enc2Next)
	elems = append(elems, enc2BPs...)
	elems = append(elems, r)
	return hashFieldElements(DomainTagKeyElem2, elems...)
}

// DeriveChallengeIdx computes H(DomainTagChallengeIdx, challengeRandomness, seed).
func DeriveChallengeIdx(challengeRandomness *big.Int, seed int) *big.Int {
	return hashFieldElements(DomainTagChallengeIdx, challengeRandomness, big.NewInt(int64(seed)))
}

// FieldModulus returns the BN254 scalar field modulus for external use.
func FieldModulus() *big.Int {
	return new(big.Int).Set(ecc.BN254.ScalarField())
}

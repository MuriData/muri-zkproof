package crypto

import (
	"crypto/rand"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// HashWithDomainTag hashes data with domain separation via the sponge
// capacity lane. Each data element is multiplied by randomness before
// absorption. The total number of absorbed elements is numChunks.
func HashWithDomainTag(tag int, data []byte, randomness *big.Int, elementSize, numChunks int) *big.Int {
	var randElement fr.Element
	randElement.SetBigInt(randomness)

	elems := make([]fr.Element, 0, numChunks)

	buf := make([]byte, elementSize)
	for offset := 0; offset < len(data); offset += elementSize {
		for i := range buf {
			buf[i] = 0
		}

		end := offset + elementSize
		if end > len(data) {
			end = len(data)
		}
		copy(buf, data[offset:end])

		var element, preImageElement fr.Element
		element.SetBytes(buf)
		preImageElement.Mul(&element, &randElement)
		elems = append(elems, preImageElement)
	}

	// Remaining zero chunks (0 * randomness = 0).
	var zero fr.Element
	for len(elems) < numChunks {
		elems = append(elems, zero)
	}

	result := SpongeHash(tag, elems)
	out := new(big.Int)
	result.BigInt(out)
	return out
}

// ComputeZeroLeafHash returns the hash of a padding (empty) leaf with
// DomainTagPadding. This is: sponge(tag=0, [0, 0, ..., 0]) with numChunks
// zero elements.
func ComputeZeroLeafHash(elementSize, numChunks int) *big.Int {
	return HashWithDomainTag(DomainTagPadding, []byte{}, big.NewInt(1), elementSize, numChunks)
}

// GenerateSecretKey generates a random secret key as a non-zero BN254
// scalar field element.
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

// DerivePublicKey computes publicKey = H(secretKey) using Poseidon2
// sponge with DomainTagPubKey, matching the circuit.
func DerivePublicKey(secretKey *big.Int) *big.Int {
	return SpongeHashBigInt(DomainTagPubKey, secretKey)
}

// DeriveAggMsg computes the aggregate message from multiple leaf hashes
// and randomness: aggMsg = H(leafHash[0], ..., leafHash[n-1], randomness).
// Uses DomainTagAggMsg for domain separation.
func DeriveAggMsg(leafHashes []*big.Int, randomness *big.Int) *big.Int {
	inputs := make([]*big.Int, 0, len(leafHashes)+1)
	inputs = append(inputs, leafHashes...)
	inputs = append(inputs, randomness)
	return SpongeHashBigInt(DomainTagAggMsg, inputs...)
}

// DeriveCommitment computes the VRF-style commitment matching the circuit:
// commitment = H(secretKey, msg, randomness, publicKey).
// Uses DomainTagCommitment for domain separation.
func DeriveCommitment(secretKey, msg, randomness, publicKey *big.Int) *big.Int {
	return SpongeHashBigInt(DomainTagCommitment, secretKey, msg, randomness, publicKey)
}

// ---------------------------------------------------------------------------
// Archive / MURI transform helpers (tags 3–6, 10–15)
// ---------------------------------------------------------------------------

// DeriveSlotLeaf computes the archive slot leaf hash:
// slotLeaf = H(DomainTagSlot, fileRoot, numChunks, cumulativeChunks)
func DeriveSlotLeaf(fileRoot, numChunks, cumulativeChunks *big.Int) *big.Int {
	return SpongeHashBigInt(DomainTagSlot, fileRoot, numChunks, cumulativeChunks)
}

// DeriveArchiveOriginalRoot computes:
// archiveOriginalRoot = H(DomainTagArchiveRoot, slotTreeRoot, totalRealChunks)
func DeriveArchiveOriginalRoot(slotTreeRoot, totalRealChunks *big.Int) *big.Int {
	return SpongeHashBigInt(DomainTagArchiveRoot, slotTreeRoot, totalRealChunks)
}

// DeriveGlobalR computes the per-replica sealing randomness:
// r = H(DomainTagGlobalR, publicKey, archiveOriginalRoot)
func DeriveGlobalR(publicKey, archiveOriginalRoot *big.Int) *big.Int {
	return SpongeHashBigInt(DomainTagGlobalR, publicKey, archiveOriginalRoot)
}

// DeriveChallengeIdx computes a challenge index derivation:
// idx = H(DomainTagChallengeIdx, randomness, k)
func DeriveChallengeIdx(randomness, k *big.Int) *big.Int {
	return SpongeHashBigInt(DomainTagChallengeIdx, randomness, k)
}

// DeriveKeySeed1 computes the Pass 1 element-0 seed key:
// key1[0] = H(DomainTagKeySeed1, r)
func DeriveKeySeed1(r *big.Int) *big.Int {
	return SpongeHashBigInt(DomainTagKeySeed1, r)
}

// DeriveKeySeed2 computes the Pass 2 element-(N-1) seed key:
// key2[N-1] = H(DomainTagKeySeed2, r)
func DeriveKeySeed2(r *big.Int) *big.Int {
	return SpongeHashBigInt(DomainTagKeySeed2, r)
}

// DeriveKeyElem1 computes the Pass 1 per-element key:
// key1[j] = H(DomainTagKeyElem1, enc1[j-1], enc1[bp[0]], ..., enc1[bp[k-1]], r)
// The caller assembles the inputs slice: [predecessor, backPointers..., r].
func DeriveKeyElem1(inputs []*big.Int) *big.Int {
	return SpongeHashBigInt(DomainTagKeyElem1, inputs...)
}

// DeriveKeyElem2 computes the Pass 2 per-element key:
// key2[j] = H(DomainTagKeyElem2, enc2[j+1], enc2[bp[0]], ..., enc2[bp[k-1]], r)
// The caller assembles the inputs slice: [successor, backPointers..., r].
func DeriveKeyElem2(inputs []*big.Int) *big.Int {
	return SpongeHashBigInt(DomainTagKeyElem2, inputs...)
}

// DeriveBackPointers computes back-pointer positions for element j:
// seed = H(domainTag, j, r)
// Positions are derived by bit-slicing the seed output.
// domainTag must be DomainTagBackPtr1 (14) or DomainTagBackPtr2 (15).
func DeriveBackPointers(domainTag int, j, r *big.Int) *big.Int {
	return SpongeHashBigInt(domainTag, j, r)
}

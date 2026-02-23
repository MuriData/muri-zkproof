package crypto

import (
	"crypto/rand"
	"math/big"

	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
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

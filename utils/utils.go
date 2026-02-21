package utils

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/MuriData/muri-zkproof/config"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	"github.com/consensys/gnark/frontend"
)

// Bytes2Field converts bytes to field elements with fixed size for circuit
func Bytes2Field(data []byte) [config.NumChunks]frontend.Variable {
	var elements [config.NumChunks]frontend.Variable

	// Re-use a single buffer to avoid per-iteration allocations. big.Int.SetBytes
	// makes its own copy so it's safe to reuse the buffer afterwards.
	buf := make([]byte, config.ElementSize)

	for i := 0; i < config.NumChunks; i++ {
		// Reset buffer in-place (cheaper than make each loop).
		for j := range buf {
			buf[j] = 0
		}

		start := i * config.ElementSize
		if start >= len(data) {
			// No more data – keep zero element.
			elements[i] = big.NewInt(0)
			continue
		}

		end := start + config.ElementSize
		if end > len(data) {
			end = len(data)
		}

		copy(buf, data[start:end])

		elements[i] = new(big.Int).SetBytes(buf)
	}

	return elements
}

// Field2Bytes converts field elements back to bytes
func Field2Bytes(elements []frontend.Variable, originalSize int) []byte {
	// Pre-allocate with exact capacity to avoid growth reallocations.
	result := make([]byte, 0, len(elements)*config.ElementSize)

	tmp := make([]byte, config.ElementSize) // reusable buffer

	for _, elem := range elements {
		// Fast-path for the common case (*big.Int produced by Bytes2Field).
		var value *big.Int
		switch v := elem.(type) {
		case *big.Int:
			value = v
		case int:
			value = big.NewInt(int64(v))
		case string:
			value = new(big.Int)
			value.SetString(v, 10)
		default:
			value = new(big.Int)
			_ = value.UnmarshalText([]byte(fmt.Sprintf("%v", v)))
		}

		// Zero the buffer then copy the value bytes at the end (big-endian).
		// If the value exceeds ElementSize bytes (e.g. a full 32-byte field
		// element), take only the least-significant ElementSize bytes to
		// avoid a negative slice index panic.
		for i := range tmp {
			tmp[i] = 0
		}
		valueBytes := value.Bytes()
		if len(valueBytes) > config.ElementSize {
			valueBytes = valueBytes[len(valueBytes)-config.ElementSize:]
		}
		copy(tmp[config.ElementSize-len(valueBytes):], valueBytes)

		result = append(result, tmp...)
	}

	if originalSize > 0 && originalSize < len(result) {
		result = result[:originalSize]
	}

	return result
}

// Hash hashes the data using the Poseidon2 hash function and the given randomness
func Hash(data []byte, randomness *big.Int) *big.Int {
	h := poseidon2.NewMerkleDamgardHasher()

	// randomness as field element (only once)
	var randElement fr.Element
	randElement.SetBigInt(randomness)

	buf := make([]byte, config.ElementSize)
	var element, preImageElement fr.Element

	for offset := 0; offset < len(data); offset += config.ElementSize {
		// Zero the buffer without reallocating.
		for i := range buf {
			buf[i] = 0
		}

		end := offset + config.ElementSize
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
	fed := (len(data) + config.ElementSize - 1) / config.ElementSize
	for ; fed < config.NumChunks; fed++ {
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

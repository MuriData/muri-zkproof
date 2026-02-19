package utils

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/MuriData/muri-zkproof/config"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr/poseidon2"
	edwardsbn254 "github.com/consensys/gnark-crypto/ecc/bn254/twistededwards"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark-crypto/signature"
	"github.com/consensys/gnark-crypto/signature/eddsa"
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

		// Zero the buffer then copy the value bytes at the end (big-endian)
		for i := range tmp {
			tmp[i] = 0
		}
		valueBytes := value.Bytes()
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

// GenerateSigner generates a new signer for the given curve
func GenerateSigner() (signature.Signer, error) {
	signer, err := eddsa.New(tedwards.BN254, rand.Reader)
	if err != nil {
		return nil, err
	}
	return signer, nil
}

// Sign signs the message using the given signer
func Sign(msg []byte, signer signature.Signer) ([]byte, error) {
	hasher := poseidon2.NewMerkleDamgardHasher()
	signature, err := signer.Sign(msg, hasher)
	if err != nil {
		return nil, err
	}
	return signature, nil
}

// SignatureRX extracts the R point's X coordinate from a BN254 EdDSA signature.
// The first 32 bytes of the signature are the compressed R point.
func SignatureRX(sig []byte) (*big.Int, error) {
	var point edwardsbn254.PointAffine
	if _, err := point.SetBytes(sig[:32]); err != nil {
		return nil, err
	}
	rx := new(big.Int)
	point.X.BigInt(rx)
	return rx, nil
}

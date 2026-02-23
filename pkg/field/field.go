package field

import (
	"fmt"
	"math/big"

	"github.com/consensys/gnark/frontend"
)

// Bytes2Field converts bytes to field elements with fixed size for circuit.
// numChunks is the total number of field elements to produce.
// elementSize is the number of bytes per field element.
func Bytes2Field(data []byte, numChunks, elementSize int) []frontend.Variable {
	elements := make([]frontend.Variable, numChunks)

	// Re-use a single buffer to avoid per-iteration allocations. big.Int.SetBytes
	// makes its own copy so it's safe to reuse the buffer afterwards.
	buf := make([]byte, elementSize)

	for i := 0; i < numChunks; i++ {
		// Reset buffer in-place (cheaper than make each loop).
		for j := range buf {
			buf[j] = 0
		}

		start := i * elementSize
		if start >= len(data) {
			// No more data – keep zero element.
			elements[i] = big.NewInt(0)
			continue
		}

		end := start + elementSize
		if end > len(data) {
			end = len(data)
		}

		copy(buf, data[start:end])

		elements[i] = new(big.Int).SetBytes(buf)
	}

	return elements
}

// Field2Bytes converts field elements back to bytes.
// elementSize is the number of bytes per field element.
func Field2Bytes(elements []frontend.Variable, elementSize, originalSize int) []byte {
	// Pre-allocate with exact capacity to avoid growth reallocations.
	result := make([]byte, 0, len(elements)*elementSize)

	tmp := make([]byte, elementSize) // reusable buffer

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
		// If the value exceeds elementSize bytes (e.g. a full 32-byte field
		// element), take only the least-significant elementSize bytes to
		// avoid a negative slice index panic.
		for i := range tmp {
			tmp[i] = 0
		}
		valueBytes := value.Bytes()
		if len(valueBytes) > elementSize {
			valueBytes = valueBytes[len(valueBytes)-elementSize:]
		}
		copy(tmp[elementSize-len(valueBytes):], valueBytes)

		result = append(result, tmp...)
	}

	if originalSize > 0 && originalSize < len(result) {
		result = result[:originalSize]
	}

	return result
}

package muri

const (
	// ElementsPerChunk is the number of field elements per 16 KB chunk.
	// 16384 / 31 = 528.5, rounded up to 529.
	ElementsPerChunk = 529

	// BackPointers is the number of random back-pointer dependencies per element (k).
	BackPointers = 5

	// BitsPerBP is the number of bits used per back-pointer position derivation.
	BitsPerBP = 50
)

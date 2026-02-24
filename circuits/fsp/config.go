package fsp

const (
	FileSize    = 16 * 1024                                   // 16 KB chunk size (must match PoI)
	ElementSize = 31                                          // bytes per field element (must match PoI)
	NumChunks   = int((FileSize + ElementSize - 1) / ElementSize) // 529 — field elements per leaf hash (must match PoI)

	MaxTreeDepth = 20
	TotalLeaves  = 1 << MaxTreeDepth // 1,048,576 leaf slots in the sparse Merkle tree
)

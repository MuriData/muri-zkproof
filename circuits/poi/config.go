package poi

const (
	FileSize    = 16 * 1024
	ElementSize = 31 // bytes
	NumChunks   = int((FileSize + ElementSize - 1) / ElementSize)

	MaxTreeDepth  = 20
	TotalLeaves   = 1 << MaxTreeDepth // 1,048,576 leaf slots in the sparse Merkle tree
	OpeningsCount = 8                 // number of parallel Merkle openings per proof
)

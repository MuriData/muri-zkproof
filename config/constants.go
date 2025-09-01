package config

const (
	FileSize    = 16 * 1024
	ElementSize = 31 // bytes
	NumChunks   = int((FileSize + ElementSize - 1) / ElementSize)

	MaxTreeDepth = 20
)

package archive_poi

import (
	"github.com/MuriData/muri-zkproof/pkg/archive"
)

const (
	OpeningsCount = 8 // number of parallel chunk openings per proof

	// Tree depth constants
	ArchiveIndexDepth = archive.ArchiveIndexDepth // 10
	FileTreeDepth     = archive.FileTreeDepth     // 20
	ArchiveTreeDepth  = archive.ArchiveTreeDepth  // 30

	// Chunk constants (same as pkg/archive)
	ElementsPerChunk = archive.ElementsPerChunk // 529
	FileSize         = archive.FileSize         // 16 KB
	ElementSize      = archive.ElementSize      // 31 bytes
	NumFieldElements = archive.NumFieldElements  // 529

	MaxFileSlots = archive.MaxFileSlots // 1024
)

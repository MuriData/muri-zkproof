package archive

const (
	// ArchiveIndexDepth is the depth of the top-level slot tree (1024 slots).
	ArchiveIndexDepth = 10

	// FileTreeDepth is the depth of each per-file subtree.
	FileTreeDepth = 20

	// ArchiveTreeDepth is the total depth of the combined archive tree (10 + 20).
	ArchiveTreeDepth = 30

	// MaxFileSlots is the maximum number of file slots in an archive.
	MaxFileSlots = 1 << ArchiveIndexDepth // 1024

	// MinArchiveChunks is the minimum number of total real chunks in an archive.
	MinArchiveChunks = 655360

	// ElementsPerChunk matches pkg/muri.ElementsPerChunk.
	ElementsPerChunk = 529

	// FileSize is the chunk size in bytes (16 KB).
	FileSize = 16 * 1024

	// ElementSize is bytes per field element.
	ElementSize = 31

	// NumFieldElements is the number of field elements per chunk leaf hash.
	NumFieldElements = int((FileSize + ElementSize - 1) / ElementSize) // 529
)

package archive_muri

import (
	"github.com/MuriData/muri-zkproof/pkg/archive"
)

const (
	// Circuit parameters (MURI.md Section 7.1)
	// Conservative profile: ~4x reduction vs full spec (C=8,R=12,H=24,Q=5)
	// Keeps all origin spot-checks and full back-pointer connectivity.
	C = 8  // spot-check chunks (origin chunks)
	R = 6  // routes per origin chunk (was 12)
	H = 12 // hops per route (was 24)
	Q = 2  // enhancement checks per route (was 5)
	K = 5  // back-pointers per element

	BitsPerBP = 50 // bits per back-pointer position

	TotalRoutes            = C * R     // 48
	TotalHops              = C * R * H // 576
	TotalEnhancementChecks = C * R * Q // 96

	// Seed offset ranges for DomainTagChallengeIdx
	SeedOffsetChunkSelection = 0                                            // [0, C)
	SeedOffsetRouteElement   = C                                            // [C, C+C*R)
	SeedOffsetHopBP          = C + C*R                                      // [C+C*R, C+C*R+C*R*H)
	SeedOffsetEnhancement    = C + C*R + C*R*H                              // [C+C*R+C*R*H, C+C*R+C*R*H+C*R*Q)

	// Tree depth constants
	ArchiveIndexDepth = archive.ArchiveIndexDepth // 10
	FileTreeDepth     = archive.FileTreeDepth     // 20
	ArchiveTreeDepth  = archive.ArchiveTreeDepth  // 30

	// Element/chunk constants
	ElementsPerChunk = archive.ElementsPerChunk // 529
	FileSize         = archive.FileSize         // 16 KB
	ElementSize      = archive.ElementSize      // 31 bytes
	NumFieldElements = archive.NumFieldElements  // 529

	MaxFileSlots = archive.MaxFileSlots // 1024
)

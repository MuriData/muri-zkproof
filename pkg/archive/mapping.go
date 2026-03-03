package archive

import "fmt"

// PhysicalMapping describes the mapping from a logical chunk to its physical tree position.
type PhysicalMapping struct {
	SlotIndex       int // File slot index in the archive (0..1023)
	LocalChunkIndex int // Chunk index within the file subtree
	PhysicalPos     int // Physical position in the depth-30 tree: slotIndex * 2^20 + localChunkIndex
}

// LogicalToPhysical maps a logical chunk index to its physical tree position.
// The logical chunk index is the position in the flat concatenated chunk array.
func LogicalToPhysical(logicalChunk int, metas []FileMeta) (PhysicalMapping, error) {
	for i, m := range metas {
		if logicalChunk >= m.CumulativeChunks && logicalChunk < m.CumulativeChunks+m.NumChunks {
			localChunkIndex := logicalChunk - m.CumulativeChunks
			physicalPos := i*(1<<FileTreeDepth) + localChunkIndex
			return PhysicalMapping{
				SlotIndex:       i,
				LocalChunkIndex: localChunkIndex,
				PhysicalPos:     physicalPos,
			}, nil
		}
	}
	return PhysicalMapping{}, fmt.Errorf("logical chunk %d not found in file metas", logicalChunk)
}

// ElementToChunk maps a flat element index to its logical chunk and element offset.
func ElementToChunk(elementIndex int) (logicalChunk int, elementOffset int) {
	logicalChunk = elementIndex / ElementsPerChunk
	elementOffset = elementIndex % ElementsPerChunk
	return
}

// TotalRealChunks computes the total number of real chunks across all file metas.
func TotalRealChunks(metas []FileMeta) int {
	if len(metas) == 0 {
		return 0
	}
	last := metas[len(metas)-1]
	return last.CumulativeChunks + last.NumChunks
}

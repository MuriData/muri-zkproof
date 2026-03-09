package crypto

// Domain separation tags for all Poseidon2 hash invocations.
// Each tag occupies the capacity lane of the sponge, ensuring
// outputs from different contexts never collide.
//
// Tags 0–15 are allocated. New tags must use values >= 16.
const (
	DomainTagPadding      = 0  // Padding chunk leaf hash
	DomainTagReal         = 1  // Real chunk leaf hash
	DomainTagNode         = 2  // Internal Merkle node hash
	DomainTagSlot         = 3  // Archive slot leaf (fileRoot, numChunks, cumulativeChunks)
	DomainTagGlobalR      = 4  // Global MURI randomness r
	DomainTagKeySeed1     = 5  // Pass 1 element-0 key derivation
	DomainTagKeyElem1     = 6  // Pass 1 per-element key
	DomainTagPubKey       = 7  // Public key derivation
	DomainTagAggMsg       = 8  // PoI aggregate message
	DomainTagCommitment   = 9  // PoI commitment
	DomainTagChallengeIdx = 10 // Challenge index derivation
	DomainTagKeySeed2     = 11 // Pass 2 element-(N-1) key derivation
	DomainTagKeyElem2     = 12 // Pass 2 per-element key
	DomainTagArchiveRoot  = 13 // Archive original root (slotTreeRoot, totalRealChunks)
	DomainTagBackPtr1     = 14 // Pass 1 back-pointer position derivation (j, r)
	DomainTagBackPtr2     = 15 // Pass 2 back-pointer position derivation (j, r)
)

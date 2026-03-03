package archive_poi

import (
	"math/big"

	"github.com/MuriData/muri-zkproof/circuits/shared"
	"github.com/MuriData/muri-zkproof/pkg/archive"
	"github.com/MuriData/muri-zkproof/pkg/crypto"
	"github.com/MuriData/muri-zkproof/pkg/merkle"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/math/bits"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/permutation/poseidon2"
)

// Precomputed zero-subtree hashes for the depth-30 tree.
var (
	zeroLeafHash          *big.Int
	zeroSubtreeHashes30   [ArchiveTreeDepth]*big.Int
	totalLeavesDepth30    = 1 << ArchiveTreeDepth
)

func init() {
	zeroLeafHash = crypto.ComputeZeroLeafHash(ElementSize, NumFieldElements)
	zh := merkle.PrecomputeZeroHashes(ArchiveTreeDepth, zeroLeafHash)
	for i := 0; i < ArchiveTreeDepth; i++ {
		zeroSubtreeHashes30[i] = zh[i]
	}
}

// SlotMappingWitness provides the slot metadata needed to map a logical chunk
// to its physical position and verify against the slot tree root.
type SlotMappingWitness struct {
	SlotIndex        frontend.Variable                           `gnark:"slotIndex"`
	FileRoot         frontend.Variable                           `gnark:"fileRoot"`
	NumChunks        frontend.Variable                           `gnark:"numChunks"`
	CumulativeChunks frontend.Variable                           `gnark:"cumulativeChunks"`
	SlotProof        shared.MerkleProof10                        `gnark:"slotProof"`
}

// OpeningWitness holds the witness data for a single archive PoI opening.
type OpeningWitness struct {
	// Chunk elements (encrypted) for leaf hash computation
	Elements [NumFieldElements]frontend.Variable `gnark:"elements"`

	// Depth-30 Merkle proof against archiveReplicaRoot
	ReplicaProof shared.MerkleProof30 `gnark:"replicaProof"`

	// Slot mapping for logical-to-physical translation
	SlotMapping SlotMappingWitness `gnark:"slotMapping"`

	// Modular reduction witnesses
	Quotient  frontend.Variable `gnark:"quotient"`
	LeafIndex frontend.Variable `gnark:"leafIndex"` // logicalChunkIdx within totalRealChunks
}

// ArchivePoICircuit proves knowledge of 8 randomly-selected encrypted chunks
// in an archive's replica Merkle tree. Public inputs: commitment, randomness,
// publicKey, archiveOriginalRoot, archiveReplicaRoot.
type ArchivePoICircuit struct {
	// Public inputs (5)
	Commitment          frontend.Variable `gnark:"commitment,public"`
	Randomness          frontend.Variable `gnark:"randomness,public"`
	PublicKey           frontend.Variable `gnark:"publicKey,public"`
	ArchiveOriginalRoot frontend.Variable `gnark:"archiveOriginalRoot,public"`
	ArchiveReplicaRoot  frontend.Variable `gnark:"archiveReplicaRoot,public"`

	// Private inputs
	SecretKey       frontend.Variable                `gnark:"secretKey"`
	SlotTreeRoot    frontend.Variable                `gnark:"slotTreeRoot"`
	TotalRealChunks frontend.Variable                `gnark:"totalRealChunks"`
	Openings        [OpeningsCount]OpeningWitness    `gnark:"openings"`
}

func (circuit *ArchivePoICircuit) Define(api frontend.API) error {
	p, err := poseidon2.NewPoseidon2FromParameters(api, 2, 6, 50)
	if err != nil {
		return err
	}

	// ---------------------------------------------------------------
	// 1. Key ownership: publicKey == H(secretKey)
	// ---------------------------------------------------------------
	api.AssertIsEqual(api.IsZero(circuit.SecretKey), 0)
	api.AssertIsEqual(api.IsZero(circuit.PublicKey), 0)

	keyHasher := hash.NewMerkleDamgardHasher(api, p, 0)
	keyHasher.Write(circuit.SecretKey)
	derivedPubKey := keyHasher.Sum()
	keyHasher.Reset()
	api.AssertIsEqual(circuit.PublicKey, derivedPubKey)

	// ---------------------------------------------------------------
	// 2. Archive root binding:
	//    archiveOriginalRoot == H(DomainTagArchiveRoot, slotTreeRoot, totalRealChunks)
	// ---------------------------------------------------------------
	rootHasher := hash.NewMerkleDamgardHasher(api, p, 0)
	rootHasher.Write(frontend.Variable(crypto.DomainTagArchiveRoot))
	rootHasher.Write(circuit.SlotTreeRoot)
	rootHasher.Write(circuit.TotalRealChunks)
	derivedOrigRoot := rootHasher.Sum()
	rootHasher.Reset()
	api.AssertIsEqual(circuit.ArchiveOriginalRoot, derivedOrigRoot)

	// ---------------------------------------------------------------
	// 3. TotalRealChunks range check (non-zero, fits in 30 bits)
	// ---------------------------------------------------------------
	api.AssertIsEqual(api.IsZero(circuit.TotalRealChunks), 0)

	// Bounded comparator for index < totalRealChunks checks.
	maxChunks := new(big.Int).SetInt64(int64(1<<ArchiveTreeDepth) + 1)
	comparator := cmp.NewBoundedComparator(api, maxChunks, false)

	// ---------------------------------------------------------------
	// 4. Per-opening verification
	// ---------------------------------------------------------------
	var leafHashes [OpeningsCount]frontend.Variable

	for k := 0; k < OpeningsCount; k++ {
		opening := &circuit.Openings[k]

		// 4a. Index derivation:
		//   r[0] = randomness
		//   r[k] = H(DomainTagChallengeIdx, randomness, k) for k >= 1
		var rawIndex frontend.Variable
		if k == 0 {
			rawIndex = circuit.Randomness
		} else {
			idxHasher := hash.NewMerkleDamgardHasher(api, p, 0)
			idxHasher.Write(frontend.Variable(crypto.DomainTagChallengeIdx))
			idxHasher.Write(circuit.Randomness)
			idxHasher.Write(frontend.Variable(k))
			rawIndex = idxHasher.Sum()
			idxHasher.Reset()
		}

		// 4b. Modular reduction: quotient * totalRealChunks + leafIndex == rawIndex
		// TotalRealChunks fits in 30 bits, rawIndex is a full field element.
		// We need the quotient to fit in the field. The quotient is rawIndex / totalRealChunks.
		product := api.Mul(opening.Quotient, circuit.TotalRealChunks)
		sum := api.Add(product, opening.LeafIndex)
		api.AssertIsEqual(sum, rawIndex)

		// Range check: leafIndex < totalRealChunks
		comparator.AssertIsLess(opening.LeafIndex, circuit.TotalRealChunks)

		// 4c. Slot mapping verification
		//     slotLeaf = H(DomainTagSlot, fileRoot, numChunks, cumulativeChunks)
		slotHasher := hash.NewMerkleDamgardHasher(api, p, 0)
		slotHasher.Write(frontend.Variable(crypto.DomainTagSlot))
		slotHasher.Write(opening.SlotMapping.FileRoot)
		slotHasher.Write(opening.SlotMapping.NumChunks)
		slotHasher.Write(opening.SlotMapping.CumulativeChunks)
		slotLeafHash := slotHasher.Sum()
		slotHasher.Reset()

		// Verify slot leaf against slotTreeRoot via depth-10 proof
		api.AssertIsEqual(opening.SlotMapping.SlotProof.LeafHash, slotLeafHash)
		slotRoot, err := opening.SlotMapping.SlotProof.ComputeRoot(api)
		if err != nil {
			return err
		}
		api.AssertIsEqual(slotRoot, circuit.SlotTreeRoot)

		// 4d. Verify leafIndex is within this slot's range:
		//     cumulativeChunks <= leafIndex < cumulativeChunks + numChunks
		comparator.AssertIsLess(
			api.Sub(opening.LeafIndex, opening.SlotMapping.CumulativeChunks),
			opening.SlotMapping.NumChunks,
		)

		// 4e. Compute leaf hash: H(DomainTagReal, elements[0..528])
		leafHasher := hash.NewMerkleDamgardHasher(api, p, 0)
		leafHasher.Write(frontend.Variable(crypto.DomainTagReal))
		leafHasher.Write(opening.Elements[:]...)
		leafHashes[k] = leafHasher.Sum()
		leafHasher.Reset()

		// 4f. Verify depth-30 Merkle proof against archiveReplicaRoot.
		//     The physical position = slotIndex * 2^20 + localChunkIndex
		//     localChunkIndex = leafIndex - cumulativeChunks
		localChunkIndex := api.Sub(opening.LeafIndex, opening.SlotMapping.CumulativeChunks)

		// Verify direction bits match the physical position.
		// Lower 20 bits: localChunkIndex
		localBits := api.ToBinary(localChunkIndex, FileTreeDepth)
		for j := 0; j < FileTreeDepth; j++ {
			api.AssertIsEqual(opening.ReplicaProof.Directions[j], localBits[j])
		}
		// Upper 10 bits: slotIndex
		slotBits := api.ToBinary(opening.SlotMapping.SlotIndex, ArchiveIndexDepth)
		for j := 0; j < ArchiveIndexDepth; j++ {
			api.AssertIsEqual(opening.ReplicaProof.Directions[FileTreeDepth+j], slotBits[j])
		}

		// Also verify slot proof directions match slotIndex
		for j := 0; j < ArchiveIndexDepth; j++ {
			api.AssertIsEqual(opening.SlotMapping.SlotProof.Directions[j], slotBits[j])
		}

		// Leaf hash binding
		api.AssertIsEqual(opening.ReplicaProof.LeafHash, leafHashes[k])

		// Verify proof
		replicaRoot, err := opening.ReplicaProof.ComputeRoot(api)
		if err != nil {
			return err
		}
		api.AssertIsEqual(replicaRoot, circuit.ArchiveReplicaRoot)
	}

	// ---------------------------------------------------------------
	// 5. Aggregate message: aggMsg = H(leafHash[0], ..., leafHash[7], randomness)
	// ---------------------------------------------------------------
	aggHasher := hash.NewMerkleDamgardHasher(api, p, 0)
	for k := 0; k < OpeningsCount; k++ {
		aggHasher.Write(leafHashes[k])
	}
	aggHasher.Write(circuit.Randomness)
	aggMsg := aggHasher.Sum()
	aggHasher.Reset()

	// ---------------------------------------------------------------
	// 6. VRF commitment: commitment = H(secretKey, aggMsg, randomness, publicKey)
	// ---------------------------------------------------------------
	vrfHasher := hash.NewMerkleDamgardHasher(api, p, 0)
	vrfHasher.Write(circuit.SecretKey)
	vrfHasher.Write(aggMsg)
	vrfHasher.Write(circuit.Randomness)
	vrfHasher.Write(circuit.PublicKey)
	derivedCommitment := vrfHasher.Sum()
	vrfHasher.Reset()

	api.AssertIsEqual(circuit.Commitment, derivedCommitment)

	return nil
}

// Ensure unused imports don't cause errors.
var _ = bits.FromBinary
var _ = archive.ArchiveIndexDepth

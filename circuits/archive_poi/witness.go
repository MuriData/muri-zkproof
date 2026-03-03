package archive_poi

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/MuriData/muri-zkproof/circuits/shared"
	"github.com/MuriData/muri-zkproof/pkg/archive"
	"github.com/MuriData/muri-zkproof/pkg/crypto"
	"github.com/MuriData/muri-zkproof/pkg/field"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark/frontend"
)

// WitnessResult holds the populated circuit assignment and diagnostic info.
type WitnessResult struct {
	Assignment   ArchivePoICircuit
	ChunkIndices [OpeningsCount]int
	PublicKey    *big.Int
	Commitment   *big.Int
}

// PrepareWitness computes all witness values for the Archive PoI circuit.
// secretKey and randomness are the prover's private inputs.
// replicaTree is the sealed replica archive tree.
// origTree is the original archive tree (for slot tree root and metadata).
// encChunks is the full set of encrypted chunk byte arrays (one per logical chunk).
func PrepareWitness(
	secretKey, randomness *big.Int,
	origTree, replicaTree *archive.ArchiveTree,
	encChunks [][]byte,
) (*WitnessResult, error) {
	metas := origTree.Metas
	totalChunks := archive.TotalRealChunks(metas)
	if totalChunks == 0 {
		return nil, fmt.Errorf("archive has no chunks")
	}
	if len(encChunks) != totalChunks {
		return nil, fmt.Errorf("encChunks count %d != totalRealChunks %d", len(encChunks), totalChunks)
	}

	publicKey := crypto.DerivePublicKey(secretKey)
	slotTreeRoot := origTree.SlotTree.Root

	var assignment ArchivePoICircuit
	assignment.SecretKey = secretKey
	assignment.Randomness = randomness
	assignment.PublicKey = publicKey
	assignment.ArchiveOriginalRoot = archive.ComputeArchiveOriginalRoot(slotTreeRoot, totalChunks)
	assignment.ArchiveReplicaRoot = replicaTree.Root()
	assignment.SlotTreeRoot = slotTreeRoot
	assignment.TotalRealChunks = totalChunks

	fieldModulus := ecc.BN254.ScalarField()
	totalChunksBig := big.NewInt(int64(totalChunks))

	type openingResult struct {
		chunkIndex int
		opening    OpeningWitness
		leafHash   *big.Int
	}
	var results [OpeningsCount]openingResult

	var wg sync.WaitGroup
	for k := 0; k < OpeningsCount; k++ {
		wg.Add(1)
		go func(k int) {
			defer wg.Done()

			// Index derivation (matches circuit)
			var rawIndexBig *big.Int
			if k == 0 {
				rawIndexBig = new(big.Int).Set(randomness)
			} else {
				rawIndexBig = crypto.DeriveChallengeIdx(randomness, k)
			}

			// Modular reduction
			quotientBig := new(big.Int).Div(rawIndexBig, totalChunksBig)
			leafIndexBig := new(big.Int).Mod(rawIndexBig, totalChunksBig)
			logicalChunk := int(leafIndexBig.Int64())

			// Map logical chunk to physical position
			mapping, err := archive.LogicalToPhysical(logicalChunk, metas)
			if err != nil {
				panic(fmt.Sprintf("mapping failed for chunk %d: %v", logicalChunk, err))
			}

			meta := metas[mapping.SlotIndex]

			// Slot proof (depth-10) against original slot tree
			slotSiblings, slotDirs := origTree.GetDepth10SlotProof(mapping.SlotIndex)
			slotLeafHash := archive.ComputeSlotLeaf(meta)

			var slotProof shared.MerkleProof10
			slotProof.LeafHash = slotLeafHash
			for j := 0; j < ArchiveIndexDepth; j++ {
				slotProof.ProofPath[j] = slotSiblings[j]
				slotProof.Directions[j] = slotDirs[j]
			}

			// Depth-30 replica proof
			replicaSiblings, replicaDirs := replicaTree.GetDepth30Proof(mapping.PhysicalPos)
			replicaLeafHash := replicaTree.GetLeafHash(mapping.PhysicalPos)

			var replicaProof shared.MerkleProof30
			replicaProof.LeafHash = replicaLeafHash
			for j := 0; j < ArchiveTreeDepth; j++ {
				replicaProof.ProofPath[j] = replicaSiblings[j]
				replicaProof.Directions[j] = replicaDirs[j]
			}

			// Convert enc chunk bytes to field elements
			chunkData := encChunks[logicalChunk]
			fieldSlice := field.Bytes2Field(chunkData, NumFieldElements, ElementSize)
			var elements [NumFieldElements]frontend.Variable
			copy(elements[:], fieldSlice)

			// Check quotient range: quotient * totalRealChunks + leafIndex == rawIndex
			// The quotient needs to be within field range
			quotientBig.Mod(quotientBig, fieldModulus)

			results[k] = openingResult{
				chunkIndex: logicalChunk,
				opening: OpeningWitness{
					Elements:     elements,
					ReplicaProof: replicaProof,
					SlotMapping: SlotMappingWitness{
						SlotIndex:        mapping.SlotIndex,
						FileRoot:         meta.FileRoot,
						NumChunks:        meta.NumChunks,
						CumulativeChunks: meta.CumulativeChunks,
						SlotProof:        slotProof,
					},
					Quotient:  quotientBig,
					LeafIndex: leafIndexBig,
				},
				leafHash: replicaLeafHash,
			}
		}(k)
	}
	wg.Wait()

	var chunkIndices [OpeningsCount]int
	var leafHashes [OpeningsCount]*big.Int
	for k := 0; k < OpeningsCount; k++ {
		chunkIndices[k] = results[k].chunkIndex
		leafHashes[k] = results[k].leafHash
		assignment.Openings[k] = results[k].opening
	}

	// Aggregate message and commitment
	aggMsg := crypto.DeriveAggMsg(leafHashes[:], randomness)
	commitment := crypto.DeriveCommitment(secretKey, aggMsg, randomness, publicKey)
	assignment.Commitment = commitment

	return &WitnessResult{
		Assignment:   assignment,
		ChunkIndices: chunkIndices,
		PublicKey:    publicKey,
		Commitment:   commitment,
	}, nil
}

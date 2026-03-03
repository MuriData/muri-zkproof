package archive_muri

import (
	"fmt"
	"math/big"
	"sync"

	"github.com/MuriData/muri-zkproof/circuits/shared"
	"github.com/MuriData/muri-zkproof/pkg/archive"
	"github.com/MuriData/muri-zkproof/pkg/crypto"
	"github.com/MuriData/muri-zkproof/pkg/field"
	"github.com/MuriData/muri-zkproof/pkg/muri"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// WitnessResult holds the populated circuit assignment.
type WitnessResult struct {
	Assignment ArchiveMURICircuit
}

// PrepareWitness computes all witness values for the Archive MURI circuit.
func PrepareWitness(
	publicKey, challengeRandomness *big.Int,
	origTree, replicaTree *archive.ArchiveTree,
	origElements, enc2Elements []fr.Element,
	enc1Elements []fr.Element, // needed for hop verification
	origChunkBytes [][]byte, // raw chunk bytes for original data
	encChunkBytes [][]byte, // raw chunk bytes for encrypted data
	globalR *big.Int,
) (*WitnessResult, error) {
	metas := origTree.Metas
	totalChunks := archive.TotalRealChunks(metas)
	if totalChunks == 0 {
		return nil, fmt.Errorf("archive has no chunks")
	}

	N := totalChunks * ElementsPerChunk
	archiveOrigRoot := archive.ComputeArchiveOriginalRoot(origTree.SlotTree.Root, totalChunks)

	var assignment ArchiveMURICircuit
	assignment.ArchiveOriginalRoot = archiveOrigRoot
	assignment.ArchiveReplicaRoot = replicaTree.Root()
	assignment.PublicKey = publicKey
	assignment.ChallengeRandomness = challengeRandomness
	assignment.SlotTreeRoot = origTree.SlotTree.Root
	assignment.TotalRealChunks = totalChunks
	assignment.GlobalR = globalR
	assignment.N = N

	// Derive spot-check chunk indices
	spotChunks := make([]int, C)
	spotChunks[0] = 0
	totalChunksBig := big.NewInt(int64(totalChunks))
	for m := 1; m < C; m++ {
		rDerived := crypto.DeriveChallengeIdx(challengeRandomness, m)
		rem := new(big.Int).Mod(rDerived, new(big.Int).Sub(totalChunksBig, big.NewInt(1)))
		spotChunks[m] = 1 + int(rem.Int64())
	}

	// Process origins in parallel
	var wg sync.WaitGroup
	for c := 0; c < C; c++ {
		wg.Add(1)
		go func(c int) {
			defer wg.Done()
			assignment.Origins[c] = prepareOriginWitness(
				c, spotChunks[c], publicKey, challengeRandomness,
				origTree, replicaTree,
				origElements, enc2Elements, enc1Elements,
				origChunkBytes, encChunkBytes,
				globalR, N, metas,
			)
		}(c)
	}
	wg.Wait()

	return &WitnessResult{Assignment: assignment}, nil
}

func prepareOriginWitness(
	c, logicalChunk int,
	publicKey, challengeRandomness *big.Int,
	origTree, replicaTree *archive.ArchiveTree,
	origElements, enc2Elements, enc1Elements []fr.Element,
	origChunkBytes, encChunkBytes [][]byte,
	globalR *big.Int,
	N int,
	metas []archive.FileMeta,
) OriginWitness {
	var origin OriginWitness
	origin.LogicalChunkIdx = logicalChunk

	// Origin chunk opening
	origin.Chunk = prepareChunkOpening(logicalChunk, origTree, replicaTree, origChunkBytes, encChunkBytes, metas)

	// Prepare routes
	for i := 0; i < R; i++ {
		routeIndex := c*R + i
		origin.Routes[i] = prepareRouteWitness(
			routeIndex, logicalChunk,
			challengeRandomness,
			origTree, replicaTree,
			origElements, enc2Elements, enc1Elements,
			origChunkBytes, encChunkBytes,
			globalR, N, metas,
		)
	}

	return origin
}

func prepareChunkOpening(
	logicalChunk int,
	origTree, replicaTree *archive.ArchiveTree,
	origChunkBytes, encChunkBytes [][]byte,
	metas []archive.FileMeta,
) ChunkOpening {
	mapping, _ := archive.LogicalToPhysical(logicalChunk, metas)
	meta := metas[mapping.SlotIndex]

	var opening ChunkOpening

	// Original elements
	origFields := field.Bytes2Field(origChunkBytes[logicalChunk], NumFieldElements, ElementSize)
	copy(opening.OrigElements[:], origFields)

	// Encrypted elements
	encFields := field.Bytes2Field(encChunkBytes[logicalChunk], NumFieldElements, ElementSize)
	copy(opening.Enc2Elements[:], encFields)

	// Original depth-20 proof
	fileSiblings, fileDirs := origTree.GetDepth20FileProof(mapping.SlotIndex, mapping.LocalChunkIndex)
	opening.OrigProof.LeafHash = origTree.FileTrees[mapping.SlotIndex].GetLeafHash(mapping.LocalChunkIndex)
	for j := 0; j < FileTreeDepth; j++ {
		opening.OrigProof.ProofPath[j] = fileSiblings[j]
		opening.OrigProof.Directions[j] = fileDirs[j]
	}

	// Replica depth-30 proof
	replicaSiblings, replicaDirs := replicaTree.GetDepth30Proof(mapping.PhysicalPos)
	opening.ReplicaProof.LeafHash = replicaTree.GetLeafHash(mapping.PhysicalPos)
	for j := 0; j < ArchiveTreeDepth; j++ {
		opening.ReplicaProof.ProofPath[j] = replicaSiblings[j]
		opening.ReplicaProof.Directions[j] = replicaDirs[j]
	}

	// Slot mapping
	opening.SlotMapping = prepareSlotMapping(mapping.SlotIndex, meta, origTree)

	return opening
}

func prepareSlotMapping(slotIndex int, meta archive.FileMeta, origTree *archive.ArchiveTree) SlotMappingWitness {
	slotSiblings, slotDirs := origTree.GetDepth10SlotProof(slotIndex)
	slotLeafHash := archive.ComputeSlotLeaf(meta)

	var proof shared.MerkleProof10
	proof.LeafHash = slotLeafHash
	for j := 0; j < ArchiveIndexDepth; j++ {
		proof.ProofPath[j] = slotSiblings[j]
		proof.Directions[j] = slotDirs[j]
	}

	return SlotMappingWitness{
		SlotIndex:        slotIndex,
		FileRoot:         meta.FileRoot,
		NumChunks:        meta.NumChunks,
		CumulativeChunks: meta.CumulativeChunks,
		SlotProof:        proof,
	}
}

func prepareRouteWitness(
	routeIndex, originChunk int,
	challengeRandomness *big.Int,
	origTree, replicaTree *archive.ArchiveTree,
	origElements, enc2Elements, enc1Elements []fr.Element,
	origChunkBytes, encChunkBytes [][]byte,
	globalR *big.Int,
	N int,
	metas []archive.FileMeta,
) RouteWitness {
	var route RouteWitness

	// Route element selection
	elemSeed := SeedOffsetRouteElement + routeIndex
	elemHash := crypto.DeriveChallengeIdx(challengeRandomness, elemSeed)
	elemOffset := new(big.Int).Mod(elemHash, big.NewInt(int64(ElementsPerChunk)))
	currentJ := originChunk*ElementsPerChunk + int(elemOffset.Int64())

	// Track element indices at each hop for enhancement checks
	hopElements := make([]int, H)

	for h := 0; h < H; h++ {
		if currentJ < 0 {
			currentJ = 0
		}
		if currentJ >= N {
			currentJ = N - 1
		}
		hopElements[h] = currentJ

		route.Hops[h] = prepareHopWitness(currentJ, origElements, enc2Elements, enc1Elements, globalR, N)

		// Next hop: alternating direction
		hopSeed := SeedOffsetHopBP + routeIndex*H + h
		s := crypto.DeriveChallengeIdx(challengeRandomness, hopSeed)
		sMod := int(new(big.Int).Mod(s, big.NewInt(int64(K))).Int64())

		if h%2 == 0 {
			// Even hop: rightward (Pass 2 back-pointers)
			if currentJ < N-1 {
				bp2 := crypto.DeriveBackPointers(currentJ, globalR, crypto.DomainTagBackPtr2, N-1-currentJ, K, BitsPerBP)
				currentJ = bp2[sMod]
			}
		} else {
			// Odd hop: leftward (Pass 1 back-pointers)
			if currentJ > 0 {
				bp1 := crypto.DeriveBackPointers(currentJ, globalR, crypto.DomainTagBackPtr1, currentJ, K, BitsPerBP)
				currentJ = bp1[sMod]
			}
		}
	}

	// Terminus
	terminusChunk := currentJ / ElementsPerChunk
	route.TerminusElemIdx = currentJ
	route.TerminusChunk = prepareChunkOpening(terminusChunk, origTree, replicaTree, origChunkBytes, encChunkBytes, metas)

	// First-hop enhancement
	firstHopChunk := hopElements[0] / ElementsPerChunk
	route.FirstHopChunk = prepareEnhancementChunk(firstHopChunk, replicaTree, encChunkBytes, metas, origTree)

	// Q intermediate enhancement checks
	for q := 0; q < Q; q++ {
		enhSeed := SeedOffsetEnhancement + routeIndex*Q + q
		enhHash := crypto.DeriveChallengeIdx(challengeRandomness, enhSeed)
		hopIdx := int(new(big.Int).Mod(enhHash, big.NewInt(int64(H))).Int64())
		enhChunk := hopElements[hopIdx] / ElementsPerChunk
		route.IntermediateChunks[q] = prepareEnhancementChunk(enhChunk, replicaTree, encChunkBytes, metas, origTree)
	}

	return route
}

func prepareHopWitness(j int, origElements, enc2Elements, enc1Elements []fr.Element, globalR *big.Int, N int) HopWitness {
	var hop HopWitness

	hop.ElemIdx = j
	hop.Enc2Val = frToBig(&enc2Elements[j])
	hop.OrigVal = frToBig(&origElements[j])

	// Pass 2 dependencies
	if j == N-1 {
		hop.Pass2Deps.IsLastElem = 1
		hop.Pass2Deps.Enc2Next = big.NewInt(0) // unused, seed key
		for m := 0; m < K; m++ {
			hop.Pass2Deps.Enc2BPs[m] = big.NewInt(0)
		}
	} else {
		hop.Pass2Deps.IsLastElem = 0
		hop.Pass2Deps.Enc2Next = frToBig(&enc2Elements[j+1])
		bp2 := crypto.DeriveBackPointers(j, globalR, crypto.DomainTagBackPtr2, N-1-j, K, BitsPerBP)
		for m := 0; m < K; m++ {
			hop.Pass2Deps.Enc2BPs[m] = frToBig(&enc2Elements[bp2[m]])
		}
	}

	// Pass 1 dependencies: positions j-1, bp1[0..K-1]
	// For each, need enc2 and its Pass 2 reversal deps
	if j == 0 {
		// Seed key, no dependencies
		for d := 0; d < K+1; d++ {
			hop.Pass1DepEnc2[d] = big.NewInt(0)
			hop.Pass1DepPass2[d].IsLastElem = 0
			hop.Pass1DepPass2[d].Enc2Next = big.NewInt(0)
			for m := 0; m < K; m++ {
				hop.Pass1DepPass2[d].Enc2BPs[m] = big.NewInt(0)
			}
		}
	} else {
		bp1 := crypto.DeriveBackPointers(j, globalR, crypto.DomainTagBackPtr1, j, K, BitsPerBP)
		depPositions := make([]int, K+1)
		depPositions[0] = j - 1
		for m := 0; m < K; m++ {
			depPositions[m+1] = bp1[m]
		}

		for d, pos := range depPositions {
			hop.Pass1DepEnc2[d] = frToBig(&enc2Elements[pos])
			hop.Pass1DepPass2[d] = preparePass2Reversal(pos, enc2Elements, globalR, N)
		}
	}

	return hop
}

func preparePass2Reversal(j int, enc2Elements []fr.Element, globalR *big.Int, N int) Pass2ReversalWitness {
	var w Pass2ReversalWitness
	if j == N-1 {
		w.IsLastElem = 1
		w.Enc2Next = big.NewInt(0)
		for m := 0; m < K; m++ {
			w.Enc2BPs[m] = big.NewInt(0)
		}
	} else {
		w.IsLastElem = 0
		w.Enc2Next = frToBig(&enc2Elements[j+1])
		bp2 := crypto.DeriveBackPointers(j, globalR, crypto.DomainTagBackPtr2, N-1-j, K, BitsPerBP)
		for m := 0; m < K; m++ {
			w.Enc2BPs[m] = frToBig(&enc2Elements[bp2[m]])
		}
	}
	return w
}

func prepareEnhancementChunk(
	logicalChunk int,
	replicaTree *archive.ArchiveTree,
	encChunkBytes [][]byte,
	metas []archive.FileMeta,
	origTree *archive.ArchiveTree,
) EnhancementChunkOpening {
	mapping, _ := archive.LogicalToPhysical(logicalChunk, metas)
	meta := metas[mapping.SlotIndex]

	var enh EnhancementChunkOpening

	encFields := field.Bytes2Field(encChunkBytes[logicalChunk], NumFieldElements, ElementSize)
	copy(enh.Enc2Elements[:], encFields)

	replicaSiblings, replicaDirs := replicaTree.GetDepth30Proof(mapping.PhysicalPos)
	enh.ReplicaProof.LeafHash = replicaTree.GetLeafHash(mapping.PhysicalPos)
	for j := 0; j < ArchiveTreeDepth; j++ {
		enh.ReplicaProof.ProofPath[j] = replicaSiblings[j]
		enh.ReplicaProof.Directions[j] = replicaDirs[j]
	}

	enh.SlotMapping = prepareSlotMapping(mapping.SlotIndex, meta, origTree)

	return enh
}

func frToBig(e *fr.Element) *big.Int {
	b := new(big.Int)
	e.BigInt(b)
	return b
}

// Ensure muri import used
var _ = muri.ElementsPerChunk

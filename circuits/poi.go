package circuits

import (
	"github.com/MuriData/muri-zkproof/config"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/permutation/poseidon2"
)

type PoICircuit struct {
	// Publics
	Commitment frontend.Variable `gnark:"commitment,public"`
	Randomness frontend.Variable `gnark:"randomness,public"`
	PublicKey  frontend.Variable `gnark:"publicKey,public"`
	RootHash   frontend.Variable `gnark:"rootHash,public"`

	// Privates
	SecretKey   frontend.Variable                   `gnark:"secretKey"`
	Bytes       [config.NumChunks]frontend.Variable `gnark:"bytes"`
	MerkleProof MerkleProofCircuit                  `gnark:"merkleProof"`
}

func (circuit *PoICircuit) Define(api frontend.API) error {
	p, err := poseidon2.NewPoseidon2FromParameters(api, 2, 6, 50)
	if err != nil {
		return err
	}

	// 1. Key ownership: publicKey == H(secretKey).
	//    The on-chain registered public key is the hash of the secret key.
	keyHasher := hash.NewMerkleDamgardHasher(api, p, 0)
	keyHasher.Write(circuit.SecretKey)
	derivedPubKey := keyHasher.Sum()
	keyHasher.Reset()

	api.AssertIsEqual(circuit.PublicKey, derivedPubKey)

	// 2. Message: msg = H(Bytes * Randomness).
	//    Binds the private data to the public randomness.
	//    Randomness must be non-zero; otherwise Bytes * 0 = 0 for all chunks
	//    and the message hash becomes constant, breaking data binding.
	api.AssertIsEqual(api.IsZero(circuit.Randomness), 0)
	msgHasher := hash.NewMerkleDamgardHasher(api, p, 0)
	var preImage [config.NumChunks]frontend.Variable
	for i := 0; i < config.NumChunks; i++ {
		preImage[i] = api.Mul(circuit.Bytes[i], circuit.Randomness)
	}
	msgHasher.Write(preImage[:]...)
	msg := msgHasher.Sum()
	msgHasher.Reset()

	// 3. VRF commitment: commitment = H(secretKey, msg, randomness, publicKey).
	//    Deterministic and uniquely bound to the secret key — prover cannot bias
	//    the output without using a different key, which fails step 1.
	vrfHasher := hash.NewMerkleDamgardHasher(api, p, 0)
	vrfHasher.Write(circuit.SecretKey)
	vrfHasher.Write(msg)
	vrfHasher.Write(circuit.Randomness)
	vrfHasher.Write(circuit.PublicKey)
	derivedCommitment := vrfHasher.Sum()
	vrfHasher.Reset()

	api.AssertIsEqual(circuit.Commitment, derivedCommitment)

	// 4. Deterministic Leaf Selection: Generate a direction bit list from randomness
	//    and ensure MerkleProof directions align with this list for all valid levels.
	//    We only need the first MaxTreeDepth bits to navigate the Merkle path, but we
	//    must *not* constrain the higher bits of `Randomness` to zero. Therefore we
	//    decompose the full 254-bit scalar (field size for BN254) and then use the
	//    first `MaxTreeDepth` bits for the direction checks.

	// BN254 scalar field size is defined in config.FieldBitLen (254 bits).
	randBitsFull := api.ToBinary(circuit.Randomness, api.Compiler().FieldBitLen())
	// Slice the bits we actually care about.
	randBits := randBitsFull[:config.MaxTreeDepth]

	for i := 0; i < config.MaxTreeDepth; i++ {
		sibling := circuit.MerkleProof.ProofPath[i]
		direction := circuit.MerkleProof.Directions[i]

		// Only enforce when the sibling hash is non-zero (i.e., this level is part of the actual proof).
		isActive := api.Sub(1, api.IsZero(sibling)) // 1 when sibling != 0

		// Mapping: if leafBit==0 (we are left), sibling is right (direction==0)
		// leafBit = 1 - randBit, so expected direction = 1 - randBit
		expectedDir := api.Sub(1, randBits[i])
		diff := api.Sub(direction, expectedDir)
		api.AssertIsEqual(api.Mul(diff, isActive), 0)
	}

	// --- Minimum proof depth ---
	// Reject 0-depth proofs where all siblings are zero. With 0-depth the
	// Merkle sub-circuit only checks leafHash == rootHash, letting a prover
	// bypass the tree structure entirely. Requiring the first sibling to be
	// non-zero ensures at least one hashing level (depth >= 1, i.e. >= 2 leaves).
	api.AssertIsEqual(api.IsZero(circuit.MerkleProof.ProofPath[0]), 0)

	// --- Proof length monotonicity ---
	// Enforce that once a zero sibling hash is encountered, all subsequent
	// levels must also have a zero sibling. This guarantees that the proof
	// is encoded contiguously (no active levels after padding).
	prevActive := frontend.Variable(1) // 1 until we encounter the first zero sibling
	for i := 0; i < config.MaxTreeDepth; i++ {
		siblingIsZero := api.IsZero(circuit.MerkleProof.ProofPath[i])
		// Disallow any non-zero sibling after we have already seen a zero.
		// Violation when (prevActive == 0) AND (siblingIsZero == 0).
		viol := api.Mul(api.Sub(1, prevActive), api.Sub(1, siblingIsZero))
		api.AssertIsEqual(viol, 0)
		// Update prevActive: stays 1 while siblingIsZero==0, flips to 0 at first zero.
		prevActive = api.Mul(prevActive, api.Sub(1, siblingIsZero))
	}

	// 5. Merkle Proof: Prove the selected data chunk (Bytes) exists at the
	//    proven LeafIndex within the committed Merkle tree (RootHash).
	// a) Compute the leaf hash from the raw data chunk.
	leafHasher := hash.NewMerkleDamgardHasher(api, p, 0)
	leafHasher.Write(circuit.Bytes[:]...)
	leafHash := leafHasher.Sum()
	leafHasher.Reset()

	// b) Link the computed leaf hash and public root hash to the sub-circuit.
	api.AssertIsEqual(circuit.MerkleProof.RootHash, circuit.RootHash)
	api.AssertIsEqual(circuit.MerkleProof.LeafValue, leafHash)

	// c) Verify the Merkle path itself. This sub-circuit call recomputes the
	//    root hash using the provided proof path and directions.
	circuit.MerkleProof.Define(api)

	return nil
}

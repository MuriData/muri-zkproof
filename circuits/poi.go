package circuits

import (
	"github.com/MuriData/muri-zkproof/config"
	tedwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash"
	"github.com/consensys/gnark/std/permutation/poseidon2"
	"github.com/consensys/gnark/std/signature/eddsa"
)

type PoICircuit struct {
	// Publics
	Commitment frontend.Variable `gnark:"commitment,public"`
	Randomness frontend.Variable `gnark:"randomness,public"`
	PublicKey  eddsa.PublicKey   `gnark:"publicKey,public"`
	RootHash   frontend.Variable `gnark:"rootHash,public"`

	// Privates
	Bytes       [config.NumChunks]frontend.Variable `gnark:"bytes"`
	Signature   eddsa.Signature                     `gnark:"signature"`
	MerkleProof MerkleProofCircuit                  `gnark:"merkleProof"`
}

func (circuit *PoICircuit) Define(api frontend.API) error {
	p, err := poseidon2.NewPoseidon2FromParameters(api, 2, 6, 50)
	if err != nil {
		return err
	}
	hasher := hash.NewMerkleDamgardHasher(api, p, 0)

	// 1. Message: Compute msg = H(Bytes * Randomness).
	// The hash binds the private data to the public randomness.
	var preImage [config.NumChunks]frontend.Variable
	for i := 0; i < config.NumChunks; i++ {
		preImage[i] = api.Mul(circuit.Bytes[i], circuit.Randomness)
	}
	hasher.Write(preImage[:]...)
	msg := hasher.Sum()
	hasher.Reset()

	// 2. Signature: Verify the EdDSA signature over msg.
	curve, err := twistededwards.NewEdCurve(api, tedwards.BN254)
	if err != nil {
		return err
	}
	err = eddsa.Verify(curve, circuit.Signature, msg, circuit.PublicKey, hasher)

	// 3. Commitment: The public commitment equals the signature's R.X (nonce point).
	// R.X is deterministic (derived from private key + msg) and unpredictable
	// without the private key, making it suitable as the next randomness.
	api.AssertIsEqual(circuit.Commitment, circuit.Signature.R.X)
	if err != nil {
		return err
	}
	hasher.Reset()

	// 3. Deterministic Leaf Selection: Generate a direction bit list from randomness
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

	// 4. Merkle Proof: Prove the selected data chunk (Bytes) exists at the
	//    proven LeafIndex within the committed Merkle tree (RootHash).
	// a) Compute the leaf hash from the raw data chunk.
	hasher.Write(circuit.Bytes[:]...)
	leafHash := hasher.Sum()
	hasher.Reset()

	// b) Link the computed leaf hash and public root hash to the sub-circuit.
	api.AssertIsEqual(circuit.MerkleProof.RootHash, circuit.RootHash)
	api.AssertIsEqual(circuit.MerkleProof.LeafValue, leafHash)

	// c) Verify the Merkle path itself. This sub-circuit call recomputes the
	//    root hash using the provided proof path and directions.
	circuit.MerkleProof.Define(api)

	return nil
}

package crypto

import (
	"fmt"
	"math/big"
)

// BN254 base field modulus P
var pBase, _ = new(big.Int).SetString("30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd47", 16)

// (P + 1) / 4 — exponent for computing square roots mod P
var expSqrt, _ = new(big.Int).SetString("0C19139CB84C680A6E14116DA060561765E05AA45A1C72A34F082305B61F3F52", 16)

// P - 2 — exponent for modular inverse via Fermat's little theorem
var expInverse = new(big.Int).Sub(pBase, big.NewInt(2))

// Fp2 constants from the gnark Solidity verifier (Fp[i]/(i²+1))
var fraction12FP, _ = new(big.Int).SetString("183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea4", 16)
var fraction2782FP, _ = new(big.Int).SetString("2b149d40ceb8aaae81be18991be06ac3b5b4c5e559dbefa33267e6dc24a138e5", 16)
var fraction382FP, _ = new(big.Int).SetString("2fcd3ac2a640a154eb23960892a85a68f031ca0c8344b23a577dcf1052b9e775", 16)

// negateFp returns P - a mod P.
func negateFp(a *big.Int) *big.Int {
	r := new(big.Int).Mod(a, pBase)
	r.Sub(pBase, r)
	r.Mod(r, pBase)
	return r
}

// sqrtFp computes sqrt(a) mod P using a^((P+1)/4).
func sqrtFp(a *big.Int) *big.Int {
	return new(big.Int).Exp(a, expSqrt, pBase)
}

// isSquareFp returns true if a is a quadratic residue mod P.
func isSquareFp(a *big.Int) bool {
	x := sqrtFp(a)
	return new(big.Int).Mod(new(big.Int).Mul(x, x), pBase).Cmp(new(big.Int).Mod(a, pBase)) == 0
}

// invertFp computes a^(-1) mod P.
func invertFp(a *big.Int) *big.Int {
	return new(big.Int).Exp(a, expInverse, pBase)
}

// mulmod returns (a * b) mod P.
func mulmod(a, b *big.Int) *big.Int {
	r := new(big.Int).Mul(a, b)
	r.Mod(r, pBase)
	return r
}

// addmod returns (a + b) mod P.
func addmod(a, b *big.Int) *big.Int {
	r := new(big.Int).Add(a, b)
	r.Mod(r, pBase)
	return r
}

// compressG1 compresses a BN254 G1 point (x, y) into a single uint256.
// Format: (x << 1) | sign_bit, where sign_bit indicates y == -sqrt(x³+3).
// Matches the gnark Solidity verifier's compress_g1 function.
func compressG1(x, y *big.Int) *big.Int {
	if x.Sign() == 0 && y.Sign() == 0 {
		return new(big.Int)
	}
	// y_pos = sqrt(x³ + 3)
	x3 := mulmod(mulmod(x, x), x)
	rhs := addmod(x3, big.NewInt(3))
	yPos := sqrtFp(rhs)

	compressed := new(big.Int).Lsh(x, 1)
	if y.Cmp(yPos) != 0 {
		// y == -yPos, set the sign bit
		compressed.Or(compressed, big.NewInt(1))
	}
	return compressed
}

// sqrtFp2 computes the square root in Fp2 = Fp[i]/(i²+1).
// Matches the Solidity verifier's sqrt_Fp2 function.
func sqrtFp2(a0, a1 *big.Int, hint bool) (x0, x1 *big.Int) {
	// d = sqrt(a0² + a1²)
	d := sqrtFp(addmod(mulmod(a0, a0), mulmod(a1, a1)))
	if hint {
		d = negateFp(d)
	}
	// x0 = sqrt((a0 + d) / 2)
	x0 = sqrtFp(mulmod(addmod(a0, d), fraction12FP))
	// x1 = a1 / (2 * x0)
	x1 = mulmod(a1, invertFp(mulmod(x0, big.NewInt(2))))
	return
}

// compressG2 compresses a BN254 G2 point (x0, x1, y0, y1) into two uint256 values.
// Format: c0 = (x0 << 2) | (hint ? 2 : 0) | sign_bit, c1 = x1.
// Matches the gnark Solidity verifier's compress_g2 function.
func compressG2(x0, x1, y0, y1 *big.Int) (c0, c1 *big.Int) {
	if x0.Sign() == 0 && x1.Sign() == 0 && y0.Sign() == 0 && y1.Sign() == 0 {
		return new(big.Int), new(big.Int)
	}

	// Compute y^2 components from x
	pMinus3 := new(big.Int).Sub(pBase, big.NewInt(3))
	n3ab := mulmod(mulmod(x0, x1), pMinus3)
	a3 := mulmod(mulmod(x0, x0), x0)
	b3 := mulmod(mulmod(x1, x1), x1)
	y0Pos := addmod(fraction2782FP, addmod(a3, mulmod(n3ab, x1)))
	y1Pos := negateFp(addmod(fraction382FP, addmod(b3, mulmod(n3ab, x0))))

	// Determine hint bit
	d := sqrtFp(addmod(mulmod(y0Pos, y0Pos), mulmod(y1Pos, y1Pos)))
	hint := !isSquareFp(mulmod(addmod(y0Pos, d), fraction12FP))

	// Recover y and determine sign
	y0Recovered, y1Recovered := sqrtFp2(y0Pos, y1Pos, hint)

	hintBit := uint(0)
	if hint {
		hintBit = 2
	}

	c1 = new(big.Int).Set(x1)

	y0Mod := new(big.Int).Mod(y0, pBase)
	y1Mod := new(big.Int).Mod(y1, pBase)
	y0RMod := new(big.Int).Mod(y0Recovered, pBase)
	y1RMod := new(big.Int).Mod(y1Recovered, pBase)

	if y0Mod.Cmp(y0RMod) == 0 && y1Mod.Cmp(y1RMod) == 0 {
		c0 = new(big.Int).Lsh(x0, 2)
		c0.Or(c0, new(big.Int).SetUint64(uint64(hintBit)|0))
	} else {
		// y == -y_pos
		c0 = new(big.Int).Lsh(x0, 2)
		c0.Or(c0, new(big.Int).SetUint64(uint64(hintBit)|1))
	}
	return
}

// CompressProof compresses a Groth16 BN254 proof from 8 uint256 (uncompressed)
// to 4 uint256 (compressed). Matches the gnark Solidity verifier's compressProof function.
//
// Input format:  [A.x, A.y, B.x1, B.x0, B.y1, B.y0, C.x, C.y]
// Output format: [compressed_A, compressed_B_c1, compressed_B_c0, compressed_C]
//
// The compressed format is:
//
//	[0] = compress_g1(A.x, A.y)
//	[1] = B.x1 (from compress_g2 c1 output)
//	[2] = (B.x0 << 2) | (hint ? 2 : 0) | sign (from compress_g2 c0 output)
//	[3] = compress_g1(C.x, C.y)
func CompressProof(proof [8]*big.Int) ([4]*big.Int, error) {
	for i, v := range proof {
		if v == nil {
			return [4]*big.Int{}, fmt.Errorf("proof element %d is nil", i)
		}
	}

	var compressed [4]*big.Int
	// compressed[0] = compress_g1(proof[0], proof[1]) — A point
	compressed[0] = compressG1(proof[0], proof[1])
	// (compressed[2], compressed[1]) = compress_g2(proof[3], proof[2], proof[5], proof[4]) — B point
	// Note: Solidity format is [A.x, A.y, B.x1, B.x0, B.y1, B.y0, C.x, C.y]
	// compress_g2 takes (x0, x1, y0, y1) = (proof[3], proof[2], proof[5], proof[4])
	compressed[2], compressed[1] = compressG2(proof[3], proof[2], proof[5], proof[4])
	// compressed[3] = compress_g1(proof[6], proof[7]) — C point
	compressed[3] = compressG1(proof[6], proof[7])

	return compressed, nil
}

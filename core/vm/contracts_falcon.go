// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package vm

import (
	"errors"

	"github.com/ethereum/go-ethereum/params"
)

const (
	falconN                   = 512
	falconQ                   = 12289
	falconBetaSq        int64 = 34034726
	falconNonceSize           = 40
	falconSigBodySize         = 625
	falconSigHdrSize          = 1
	falconSigHeader           = 0x39
	falconMsgSize             = 32
	falconSigSize             = 666
	falconPKSize              = 896
	falconChallengeSize       = falconPKSize // 512 coefficients × 14 bits

	falconHashToPointInputSize = falconMsgSize + falconSigSize
	falconCoreInputSize        = falconSigSize + falconPKSize + falconChallengeSize

	// Falcon's q supports a primitive 1024th root because q-1 = 12*1024.
	// psi is a primitive 1024th root and omega=psi² is a primitive 512th root.
	falconNTTPsi      int32 = 10302
	falconNTTOmega    int32 = 3400
	falconNTTInvOmega int32 = 2859
	falconNTTInvN     int32 = 12265
	falconNTTInvPsi   int32 = 8974
)

var errFalconInvalidInputLength = errors.New("invalid Falcon precompile input length")

var (
	nttRoots         = falconRootPowers(falconNTTOmega)
	nttInverseRoots  = falconRootPowers(falconNTTInvOmega)
	nttTwistRoots    = falconRootPowers(falconNTTPsi)
	nttInvTwistRoots = falconRootPowers(falconNTTInvPsi)
)

// falconHashToPointShake256 is a stub precompile for EIP-8052
// FALCON_HASH_TO_POINT_SHAKE256.
type falconHashToPointShake256 struct{}

func (c *falconHashToPointShake256) RequiredGas(input []byte) uint64 {
	return params.FalconHashToPointGas
}

func (c *falconHashToPointShake256) Run(input []byte) ([]byte, error) {
	if len(input) < falconSigSize {
		return nil, errFalconInvalidInputLength
	}
	msg := input[:len(input)-falconSigSize]
	sig := input[len(input)-falconSigSize:]
	nonce := sig[falconSigHdrSize : falconSigHdrSize+falconNonceSize]
	poly := falconHashToPoint(nonce, msg, false)
	return falconEncodePolynomial(poly), nil
}

func (c *falconHashToPointShake256) Name() string { return "FALCON_HASH_TO_POINT_SHAKE256" }

// falconHashToPointKeccakPRNG is a stub precompile for EIP-8052
// FALCON_HASH_TO_POINT_KECCAKPRNG.
type falconHashToPointKeccakPRNG struct{}

func (c *falconHashToPointKeccakPRNG) RequiredGas(input []byte) uint64 {
	return params.FalconHashToPointGas
}

func (c *falconHashToPointKeccakPRNG) Run(input []byte) ([]byte, error) {
	if len(input) < falconSigSize {
		return nil, errFalconInvalidInputLength
	}
	msg := input[:len(input)-falconSigSize]
	sig := input[len(input)-falconSigSize:]
	nonce := sig[falconSigHdrSize : falconSigHdrSize+falconNonceSize]
	poly := falconHashToPoint(nonce, msg, true)
	return falconEncodePolynomial(poly), nil
}

func (c *falconHashToPointKeccakPRNG) Name() string { return "FALCON_HASH_TO_POINT_KECCAKPRNG" }

// falconCore is a stub precompile for EIP-8052 FALCON_CORE.
type falconCore struct{}

func (c *falconCore) RequiredGas(input []byte) uint64 { return params.FalconCoreGas }

func (c *falconCore) Run(input []byte) ([]byte, error) {
	if len(input) != falconCoreInputSize {
		return nil, errFalconInvalidInputLength
	}

	// Prefer the historical repo ABI, then fall back to the EIP-8052-style
	// challenge || sig || pk layout. Header bytes alone are ambiguous because
	// challenge coefficients may start with 0x39.
	if input[0] == falconSigHeader {
		if falconCoreVerify(
			input[:falconSigSize],
			input[falconSigSize:falconSigSize+falconPKSize],
			input[falconSigSize+falconPKSize:],
		) {
			return true32Byte, nil
		}
	}
	if input[falconChallengeSize] == falconSigHeader {
		if falconCoreVerify(
			input[falconChallengeSize:falconChallengeSize+falconSigSize],
			input[falconChallengeSize+falconSigSize:],
			input[:falconChallengeSize],
		) {
			return true32Byte, nil
		}
	}
	return false32Byte, nil
}

func falconCoreVerify(sig, pkRaw, challengeRaw []byte) bool {
	if sig[0] != falconSigHeader {
		return false
	}
	sigBody := sig[falconSigHdrSize+falconNonceSize:]

	h, ok := falconDecodePK(pkRaw)
	if !ok {
		return false
	}
	s2, ok := falconDecompressSig(sigBody)
	if !ok {
		return false
	}
	challenge, ok := falconDecodePolynomial(challengeRaw)
	if !ok {
		return false
	}
	hs2 := falconPolyMulNTT(h, s2)
	s1 := falconPolySub(challenge, hs2)
	if !falconNormCheck(s1, s2) {
		return false
	}
	return true
}

func (c *falconCore) Name() string { return "FALCON_CORE" }

// ---------------------------------------------------------------------------
// Public key decoding
// ---------------------------------------------------------------------------

// falconEncodePolynomial packs falconN coefficients into the EIP-8052
// big-endian 14-bit polynomial encoding.
func falconEncodePolynomial(poly [falconN]int32) []byte {
	data := make([]byte, falconPKSize)
	acc := uint64(0)
	accLen := uint(0)
	off := 0
	for _, v := range poly {
		acc = (acc << 14) | uint64(v)
		accLen += 14
		for accLen >= 8 {
			accLen -= 8
			data[off] = byte(acc >> accLen)
			off++
		}
	}
	return data
}

// falconDecodePolynomial unpacks falconN big-endian 14-bit coefficients.
func falconDecodePolynomial(data []byte) ([falconN]int32, bool) {
	var poly [falconN]int32
	acc := uint32(0)
	accLen := uint(0)
	off := 0
	for i := 0; i < falconN; i++ {
		for accLen < 14 {
			if off >= len(data) {
				return poly, false
			}
			acc = (acc << 8) | uint32(data[off])
			accLen += 8
			off++
		}
		accLen -= 14
		v := int32((acc >> accLen) & 0x3FFF)
		if v >= falconQ {
			return poly, false
		}
		poly[i] = v
	}
	if accLen > 0 && acc&((1<<accLen)-1) != 0 {
		return poly, false
	}
	return poly, true
}

// falconDecodePK unpacks a Falcon-512 public key polynomial.
func falconDecodePK(data []byte) ([falconN]int32, bool) {
	return falconDecodePolynomial(data)
}

// ---------------------------------------------------------------------------
// Signature decompression
// ---------------------------------------------------------------------------

// falconBitReader reads bits MSB-first from a byte slice.
type falconBitReader struct {
	data    []byte
	byteOff int
	acc     uint32
	accLen  uint
}

func (r *falconBitReader) refill() bool {
	if r.byteOff >= len(r.data) {
		return false
	}
	r.acc = (r.acc << 8) | uint32(r.data[r.byteOff])
	r.byteOff++
	r.accLen += 8
	return true
}

func (r *falconBitReader) read1() (uint32, bool) {
	if r.accLen == 0 && !r.refill() {
		return 0, false
	}
	r.accLen--
	bit := (r.acc >> r.accLen) & 1
	return bit, true
}

func (r *falconBitReader) read8() (uint32, bool) {
	for r.accLen < 8 {
		if !r.refill() {
			return 0, false
		}
	}
	r.accLen -= 8
	bits := (r.acc >> r.accLen) & 0xFF
	return bits, true
}

// falconDecompressSig decodes falconN signed integer coefficients from the
// 625-byte padded compressed signature. Encoding per Falcon spec §3.11.2:
// sign(1) | low7(7) | unary(high) where coeff = sign × (low7 + 128*high).
func falconDecompressSig(data []byte) ([falconN]int32, bool) {
	var s2 [falconN]int32
	br := &falconBitReader{data: data}

	for i := 0; i < falconN; i++ {
		b, ok := br.read8()
		if !ok {
			return s2, false
		}
		s := b & 0x80
		coeff := int32(b & 0x7F)
		// Read unary-encoded high part: count leading zeros until stop bit 1.
		for {
			b, ok := br.read1()
			if !ok {
				return s2, false
			}
			if b == 1 {
				break
			}
			coeff += 128
			if coeff > 2047 {
				return s2, false
			}
		}
		if s != 0 {
			if coeff == 0 {
				// Negative zero is invalid per spec.
				return s2, false
			}
			coeff = -coeff
		}
		s2[i] = coeff
	}

	// Remaining bits in the padded buffer must all be zero.
	if br.accLen > 0 {
		mask := uint32((1 << br.accLen) - 1)
		if br.acc&mask != 0 {
			return s2, false
		}
	}
	for br.byteOff < len(br.data) {
		if br.data[br.byteOff] != 0 {
			return s2, false
		}
		br.byteOff++
	}

	return s2, true
}

// ---------------------------------------------------------------------------
// HashToPoint (Falcon spec §3.12.1)
// ---------------------------------------------------------------------------

// falconHashToPoint maps (nonce ‖ msg) to a polynomial c ∈ Z_q[x]/(x^n+1)
// using rejection sampling on the XOF output.
func falconHashToPoint(nonce, msg []byte, useKeccak bool) [falconN]int32 {
	var c [falconN]int32

	xof := mldsaNewXOF(useKeccak) // reuse XOF from ML-DSA (SHAKE256 or keccakPRNG)
	xof.Write(nonce)
	xof.Write(msg)

	// Accept 16-bit values < limit to ensure uniform distribution over Z_q.
	// limit = floor(65536/q)*q = 5*12289 = 61445.
	const limit = uint32((65536 / falconQ) * falconQ)

	var buf [2]byte
	for i := 0; i < falconN; {
		xof.Read(buf[:])
		v := uint32(buf[0])<<8 | uint32(buf[1]) // big-endian 16-bit
		if v < limit {
			c[i] = int32(v % falconQ)
			i++
		}
	}
	return c
}

// ---------------------------------------------------------------------------
// Polynomial arithmetic in Z_q[x]/(x^n+1)
// ---------------------------------------------------------------------------

func falconMod(value int64) int32 {
	value %= int64(falconQ)
	if value < 0 {
		value += int64(falconQ)
	}
	return int32(value)
}

func falconRootPowers(root int32) [falconN]int32 {
	var powers [falconN]int32
	powers[0] = 1
	for i := 1; i < falconN; i++ {
		powers[i] = int32(int64(powers[i-1]) * int64(root) % int64(falconQ))
	}
	return powers
}

// falconNTT computes a cyclic size-512 NTT using omega, a primitive 512th
// root of unity. Inputs are normalized into [0,q-1].
func falconNTT(a [falconN]int32) [falconN]int32 {
	for i := 0; i < falconN; i++ {
		a[i] = falconMod(int64(a[i]))
	}
	falconBitReverse(&a)

	for length := 2; length <= falconN; length <<= 1 {
		rootStep := nttRoots[falconN/length]
		half := length >> 1
		for offset := 0; offset < falconN; offset += length {
			root := int32(1)
			for j := 0; j < half; j++ {
				even := a[offset+j]
				odd := int32(int64(a[offset+j+half]) * int64(root) % int64(falconQ))

				sum := even + odd
				if sum >= falconQ {
					sum -= falconQ
				}
				diff := even - odd
				if diff < 0 {
					diff += falconQ
				}
				a[offset+j] = sum
				a[offset+j+half] = diff
				root = int32(int64(root) * int64(rootStep) % int64(falconQ))
			}
		}
	}
	return a
}

// falconINTT computes the inverse cyclic size-512 NTT.
func falconINTT(a [falconN]int32) [falconN]int32 {
	for i := 0; i < falconN; i++ {
		a[i] = falconMod(int64(a[i]))
	}
	falconBitReverse(&a)

	for length := 2; length <= falconN; length <<= 1 {
		rootStep := nttInverseRoots[falconN/length]
		half := length >> 1
		for offset := 0; offset < falconN; offset += length {
			root := int32(1)
			for j := 0; j < half; j++ {
				even := a[offset+j]
				odd := int32(int64(a[offset+j+half]) * int64(root) % int64(falconQ))

				sum := even + odd
				if sum >= falconQ {
					sum -= falconQ
				}
				diff := even - odd
				if diff < 0 {
					diff += falconQ
				}
				a[offset+j] = sum
				a[offset+j+half] = diff
				root = int32(int64(root) * int64(rootStep) % int64(falconQ))
			}
		}
	}
	for i := 0; i < falconN; i++ {
		a[i] = int32(int64(a[i]) * int64(falconNTTInvN) % int64(falconQ))
	}
	return a
}

func falconBitReverse(a *[falconN]int32) {
	for i, j := 1, 0; i < falconN; i++ {
		bit := falconN >> 1
		for ; j&bit != 0; bit >>= 1 {
			j ^= bit
		}
		j ^= bit
		if i < j {
			a[i], a[j] = a[j], a[i]
		}
	}
}

// falconPolyMulNTT multiplies in Z_q[x]/(x^512+1). Multiplying coefficient i
// by psi^i maps negacyclic convolution to cyclic convolution under omega=psi².
func falconPolyMulNTT(a, b [falconN]int32) [falconN]int32 {
	for i := 0; i < falconN; i++ {
		a[i] = int32(int64(falconMod(int64(a[i]))) * int64(nttTwistRoots[i]) % int64(falconQ))
		b[i] = int32(int64(falconMod(int64(b[i]))) * int64(nttTwistRoots[i]) % int64(falconQ))
	}
	a = falconNTT(a)
	b = falconNTT(b)
	for i := 0; i < falconN; i++ {
		a[i] = int32(int64(a[i]) * int64(b[i]) % int64(falconQ))
	}
	a = falconINTT(a)
	for i := 0; i < falconN; i++ {
		a[i] = int32(int64(a[i]) * int64(nttInvTwistRoots[i]) % int64(falconQ))
	}
	return a
}

// falconPolyMulSchoolbook multiplies two polynomials modulo (x^n+1, q) using
// schoolbook O(n²) multiplication. It is retained as a correctness reference.
func falconPolyMulSchoolbook(a, b [falconN]int32) [falconN]int32 {
	var acc [falconN]int64
	for i := 0; i < falconN; i++ {
		for j := 0; j < falconN; j++ {
			k := i + j
			prod := int64(a[i]) * int64(b[j])
			if k < falconN {
				acc[k] += prod
			} else {
				// x^n ≡ −1 mod (x^n+1): subtract from wrapped index
				acc[k-falconN] -= prod
			}
		}
	}
	var result [falconN]int32
	for i := 0; i < falconN; i++ {
		result[i] = falconMod(acc[i])
	}
	return result
}

// falconPolySub computes a − b coefficient-wise mod q.
// Inputs are in [0, q−1]; result is in [0, q−1].
func falconPolySub(a, b [falconN]int32) [falconN]int32 {
	var c [falconN]int32
	for i := 0; i < falconN; i++ {
		r := a[i] - b[i]
		if r < 0 {
			r += falconQ
		}
		c[i] = r
	}
	return c
}

// ---------------------------------------------------------------------------
// Norm check
// ---------------------------------------------------------------------------

// falconNormCheck verifies ‖s1‖² + ‖s2‖² ≤ β².
// s1 is in [0, q−1] (centered before squaring); s2 is already signed.
func falconNormCheck(s1, s2 [falconN]int32) bool {
	var sq int64
	for i := 0; i < falconN; i++ {
		// Center s1[i] from [0, q−1] to [−(q−1)/2, (q−1)/2].
		v1 := int64(s1[i])
		if v1 > int64(falconQ)/2 {
			v1 -= int64(falconQ)
		}
		sq += v1 * v1

		v2 := int64(s2[i])
		sq += v2 * v2

		// Early exit once bound exceeded.
		if sq > falconBetaSq {
			return false
		}
	}
	return true
}

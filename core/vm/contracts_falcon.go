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

import "github.com/ethereum/go-ethereum/params"

// Falcon-512 parameters (NIST submission, round 3).
const (
	falconN    = 512
	falconQ    = 12289
	falconLogN = 9

	// Norm bound: valid signatures satisfy ‖(s1,s2)‖² ≤ falconBetaSq.
	falconBetaSq int64 = 34034726

	// Input layout (no wire-format headers; caller provides raw fields).
	falconMsgSize   = 32  // message hash
	falconNonceSize = 40  // HashToPoint nonce r
	falconSigSize   = 625 // padded compressed s2 (FALCONPADDED512 − 1 hdr − 40 nonce)
	falconPKSize    = 896 // h polynomial: falconN coefficients × 14 bits = 896 bytes
	falconInputSize = falconMsgSize + falconNonceSize + falconSigSize + falconPKSize // 1593
)

// ---------------------------------------------------------------------------
// Precompile structs
// ---------------------------------------------------------------------------

// verifyFalcon implements Falcon-512 verification at address 0x14.
// Uses NIST-compliant SHAKE256 for HashToPoint.
type verifyFalcon struct{}

func (c *verifyFalcon) RequiredGas(_ []byte) uint64 { return params.VerifyFalconGas }
func (c *verifyFalcon) Run(input []byte) ([]byte, error) {
	return verifyFalconCore(input, false)
}
func (c *verifyFalcon) Name() string { return "VERIFY_FALCON" }

// verifyFalconEth implements Falcon-512 verification at address 0x15.
// Uses Keccak-based PRNG instead of SHAKE256 for EVM efficiency.
type verifyFalconEth struct{}

func (c *verifyFalconEth) RequiredGas(_ []byte) uint64 { return params.VerifyFalconGas }
func (c *verifyFalconEth) Run(input []byte) ([]byte, error) {
	return verifyFalconCore(input, true)
}
func (c *verifyFalconEth) Name() string { return "VERIFY_FALCON_ETH" }

// ---------------------------------------------------------------------------
// Core verification (Falcon spec §3.11.3)
// ---------------------------------------------------------------------------

func verifyFalconCore(input []byte, useKeccak bool) ([]byte, error) {
	if len(input) != falconInputSize {
		return nil, nil
	}

	msg    := input[:falconMsgSize]
	nonce  := input[falconMsgSize : falconMsgSize+falconNonceSize]
	sigRaw := input[falconMsgSize+falconNonceSize : falconMsgSize+falconNonceSize+falconSigSize]
	pkRaw  := input[falconMsgSize+falconNonceSize+falconSigSize:]

	// 1. Decode public key h ∈ Z_q[x]/(x^n+1).
	h, ok := falconDecodePK(pkRaw)
	if !ok {
		return false32Byte, nil
	}

	// 2. Decompress signature polynomial s2.
	s2, ok := falconDecompressSig(sigRaw)
	if !ok {
		return false32Byte, nil
	}

	// 3. HashToPoint: c = SHAKE256(nonce ‖ msg) mod (q, x^n+1).
	c := falconHashToPoint(nonce, msg, useKeccak)

	// 4. Recover s1 = c − h·s2  (mod q, x^n+1).
	hs2 := falconPolyMul(h, s2)
	s1  := falconPolySub(c, hs2)

	// 5. Verify norm bound: ‖s1‖² + ‖s2‖² ≤ β².
	if !falconNormCheck(s1, s2) {
		return false32Byte, nil
	}
	return true32Byte, nil
}

// ---------------------------------------------------------------------------
// Public key decoding
// ---------------------------------------------------------------------------

// falconDecodePK unpacks falconN 14-bit unsigned coefficients from data.
// data must be exactly falconPKSize (896) bytes.
func falconDecodePK(data []byte) ([falconN]int32, bool) {
	var h [falconN]int32
	acc := uint32(0)
	accLen := uint(0)
	off := 0
	for i := 0; i < falconN; i++ {
		for accLen < 14 {
			if off >= len(data) {
				return h, false
			}
			acc |= uint32(data[off]) << accLen
			accLen += 8
			off++
		}
		v := int32(acc & 0x3FFF)
		acc >>= 14
		accLen -= 14
		if v >= falconQ {
			return h, false
		}
		h[i] = v
	}
	return h, true
}

// ---------------------------------------------------------------------------
// Signature decompression
// ---------------------------------------------------------------------------

// falconBitReader reads bits LSB-first from a byte slice.
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
	r.acc |= uint32(r.data[r.byteOff]) << r.accLen
	r.byteOff++
	r.accLen += 8
	return true
}

func (r *falconBitReader) read1() (uint32, bool) {
	if r.accLen == 0 && !r.refill() {
		return 0, false
	}
	bit := r.acc & 1
	r.acc >>= 1
	r.accLen--
	return bit, true
}

func (r *falconBitReader) read7() (uint32, bool) {
	for r.accLen < 7 {
		if !r.refill() {
			return 0, false
		}
	}
	bits := r.acc & 0x7F
	r.acc >>= 7
	r.accLen -= 7
	return bits, true
}

// falconDecompressSig decodes falconN signed integer coefficients from the
// 625-byte padded compressed signature. Encoding per Falcon spec §3.11.2:
// sign(1) | low7(7) | unary(high) where coeff = sign × ((high<<7)|low7).
func falconDecompressSig(data []byte) ([falconN]int32, bool) {
	var s2 [falconN]int32
	br := &falconBitReader{data: data}

	for i := 0; i < falconN; i++ {
		s, ok := br.read1()
		if !ok {
			return s2, false
		}
		low7, ok := br.read7()
		if !ok {
			return s2, false
		}
		// Read unary-encoded high part: count leading zeros until stop bit 1.
		high := 0
		for {
			b, ok := br.read1()
			if !ok {
				return s2, false
			}
			if b == 1 {
				break
			}
			high++
			// Bound prevents runaway on malformed input; max valid high ≈ 45.
			if high > 63 {
				return s2, false
			}
		}
		coeff := int32((high << 7) | int(low7))
		if s == 1 {
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
		v := uint32(buf[0]) | uint32(buf[1])<<8 // little-endian 16-bit
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

// falconPolyMul multiplies two polynomials modulo (x^n+1, q) using
// schoolbook O(n²) multiplication. Intermediate sums use int64 to
// avoid overflow (max |accumulator| ≈ 512 × 12288 × 8192 ≈ 5×10^10).
func falconPolyMul(a, b [falconN]int32) [falconN]int32 {
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
		r := acc[i] % int64(falconQ)
		if r < 0 {
			r += int64(falconQ)
		}
		result[i] = int32(r)
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

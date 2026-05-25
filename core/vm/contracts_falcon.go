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
  falconN           = 512
  falconQ           = 12289
  falconBetaSq      int64 = 34034726
  falconNonceSize   = 40
  falconSigBodySize = 625
  falconSigHdrSize  = 1
  falconSigHeader   = 0x39
	falconMsgSize       = 32
	falconSigSize       = 666
	falconPKSize        = 896
	falconChallengeSize = falconN * 2 // 512 coefficients × 2 bytes (16-bit LE)

	falconHashToPointInputSize = falconMsgSize + falconSigSize
	falconCoreInputSize        = falconSigSize + falconPKSize + falconChallengeSize
)

var errFalconInvalidInputLength = errors.New("invalid Falcon precompile input length")

// falconHashToPointShake256 is a stub precompile for EIP-8052
// FALCON_HASH_TO_POINT_SHAKE256.
type falconHashToPointShake256 struct{}

func (c *falconHashToPointShake256) RequiredGas(input []byte) uint64 {
	return params.FalconHashToPointGas
}

func (c *falconHashToPointShake256) Run(input []byte) ([]byte, error) {
	if len(input) != falconHashToPointInputSize {
		return nil, errFalconInvalidInputLength
	}
	msg   := input[:falconMsgSize]
	nonce := input[falconMsgSize+falconSigHdrSize : falconMsgSize+falconSigHdrSize+falconNonceSize]
	poly  := falconHashToPoint(nonce, msg, false)
	out   := make([]byte, falconChallengeSize)
	for i, v := range poly {
		out[2*i]   = byte(uint16(v))
		out[2*i+1] = byte(uint16(v) >> 8)
	}
	return out, nil
}


func (c *falconHashToPointShake256) Name() string { return "FALCON_HASH_TO_POINT_SHAKE256" }

// falconHashToPointKeccakPRNG is a stub precompile for EIP-8052
// FALCON_HASH_TO_POINT_KECCAKPRNG.
type falconHashToPointKeccakPRNG struct{}

func (c *falconHashToPointKeccakPRNG) RequiredGas(input []byte) uint64 {
	return params.FalconHashToPointGas
}

func (c *falconHashToPointKeccakPRNG) Run(input []byte) ([]byte, error) {
	if len(input) != falconHashToPointInputSize {
		return nil, errFalconInvalidInputLength
	}
	msg   := input[:falconMsgSize]
	nonce := input[falconMsgSize+falconSigHdrSize : falconMsgSize+falconSigHdrSize+falconNonceSize]
	poly  := falconHashToPoint(nonce, msg, true)
	out   := make([]byte, falconChallengeSize)
	for i, v := range poly {
		out[2*i]   = byte(uint16(v))
		out[2*i+1] = byte(uint16(v) >> 8)
	}
	return out, nil
}

func (c *falconHashToPointKeccakPRNG) Name() string { return "FALCON_HASH_TO_POINT_KECCAKPRNG" }

// falconCore is a stub precompile for EIP-8052 FALCON_CORE.
type falconCore struct{}

func (c *falconCore) RequiredGas(input []byte) uint64 { return params.FalconCoreGas }

func (c *falconCore) Run(input []byte) ([]byte, error) {
	if len(input) != falconCoreInputSize {
		return nil, errFalconInvalidInputLength
	}
	sig          := input[:falconSigSize]
	pkRaw        := input[falconSigSize : falconSigSize+falconPKSize]
	challengeRaw := input[falconSigSize+falconPKSize:]

	if sig[0] != falconSigHeader {
		return false32Byte, nil
	}
	sigBody := sig[falconSigHdrSize+falconNonceSize:]

	h, ok := falconDecodePK(pkRaw)
	if !ok {
		return false32Byte, nil
	}
	s2, ok := falconDecompressSig(sigBody)
	if !ok {
		return false32Byte, nil
	}
	var challenge [falconN]int32
	for i := range challenge {
		lo := uint16(challengeRaw[2*i])
		hi := uint16(challengeRaw[2*i+1])
		v  := int32(lo | hi<<8)
		if v < 0 || v >= falconQ {
			return false32Byte, nil
		}
		challenge[i] = v
	}
	hs2 := falconPolyMul(h, s2)
	s1  := falconPolySub(challenge, hs2)
	if !falconNormCheck(s1, s2) {
		return false32Byte, nil
	}
	return true32Byte, nil
}

func (c *falconCore) Name() string { return "FALCON_CORE" }

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

// Copyright 2025 The go-ethereum Authors
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
	"math/big"
	"math/bits"

	"github.com/ethereum/go-ethereum/params"
)

// NTT precompile error sentinels.
var (
	errNTTInvalidInputLength  = errors.New("invalid NTT input length")
	errNTTInvalidDegree       = errors.New("NTT degree must be a power of 2 and >= 2")
	errNTTModulusZero         = errors.New("NTT modulus must be > 0")
	errNTTCoefficientTooLarge = errors.New("NTT coefficient >= modulus")
	errNTTDegreeTooLarge      = errors.New("NTT degree exceeds maximum allowed")
	errNTTNoInverse           = errors.New("n has no modular inverse mod q")
)

const (
	nttMaxDegree   = 65536 // Safety cap: max vector length = 2^16
	nttElementSize = 32    // Each element is a uint256 (32 bytes big-endian)
	nttHeaderSize  = 64    // q (32 bytes) + n (32 bytes)
)

// parseNTTHeader extracts q (modulus) and n (degree/vector-length) from the
// first 64 bytes of input.
func parseNTTHeader(input []byte) (q *big.Int, n uint64, err error) {
	if len(input) < nttHeaderSize {
		return nil, 0, errNTTInvalidInputLength
	}
	q = new(big.Int).SetBytes(input[0:32])
	if q.Sign() <= 0 {
		return nil, 0, errNTTModulusZero
	}
	nBig := new(big.Int).SetBytes(input[32:64])
	if !nBig.IsUint64() || nBig.Uint64() > nttMaxDegree {
		return nil, 0, errNTTDegreeTooLarge
	}
	n = nBig.Uint64()
	if n < 2 || (n&(n-1)) != 0 {
		return nil, 0, errNTTInvalidDegree
	}
	return q, n, nil
}

// parseNTTVector extracts n big.Int coefficients from input starting at offset.
// Each coefficient is 32 bytes big-endian. Validates each < q.
func parseNTTVector(input []byte, offset int, n uint64, q *big.Int) ([]*big.Int, error) {
	end := offset + int(n)*nttElementSize
	if end > len(input) {
		return nil, errNTTInvalidInputLength
	}
	vec := make([]*big.Int, n)
	for i := uint64(0); i < n; i++ {
		start := offset + int(i)*nttElementSize
		val := new(big.Int).SetBytes(input[start : start+nttElementSize])
		if val.Cmp(q) >= 0 {
			return nil, errNTTCoefficientTooLarge
		}
		vec[i] = val
	}
	return vec, nil
}

// encodeNTTOutput encodes a vector of big.Int values as n*32 bytes output.
func encodeNTTOutput(vec []*big.Int) []byte {
	out := make([]byte, len(vec)*nttElementSize)
	for i, v := range vec {
		b := v.Bytes()
		copy(out[i*nttElementSize+(nttElementSize-len(b)):], b)
	}
	return out
}

// nttComputeK returns the smallest power of 2 >= ceil(log2(q)).
func nttComputeK(q *big.Int) uint64 {
	bitLen := uint64(q.BitLen())
	if bitLen <= 1 {
		return 1
	}
	// bits.Len64 of (bitLen-1) gives the position of the highest bit,
	// which when used as 1 << that gives the next power of 2 >= bitLen.
	return 1 << uint(bits.Len64(bitLen-1))
}

// nttForward implements the EIP-NTT NTT_FW precompile at address 0x0101.
// It performs the forward NTT transformation using the Cooley-Tukey butterfly.
type nttForward struct{}

func (c *nttForward) RequiredGas(input []byte) uint64 {
	return params.NttFwGas
}

func (c *nttForward) Run(input []byte) ([]byte, error) {
	q, n, err := parseNTTHeader(input)
	if err != nil {
		return nil, err
	}
	expectedLen := nttHeaderSize + int(n)*nttElementSize*2
	if len(input) != expectedLen {
		return nil, errNTTInvalidInputLength
	}

	a, err := parseNTTVector(input, nttHeaderSize, n, q)
	if err != nil {
		return nil, err
	}
	psiRev, err := parseNTTVector(input, nttHeaderSize+int(n)*nttElementSize, n, q)
	if err != nil {
		return nil, err
	}

	// Cooley-Tukey butterfly (in-place)
	// Temp variables to reduce allocations
	U := new(big.Int)
	V := new(big.Int)

	t := n
	for m := uint64(1); m < n; m *= 2 {
		t /= 2
		for i := uint64(0); i < m; i++ {
			j1 := 2 * i * t
			j2 := j1 + t
			S := psiRev[m+i]
			for j := j1; j < j2; j++ {
				U.Set(a[j])
				V.Mul(a[j+t], S)
				V.Mod(V, q)
				a[j].Add(U, V)
				a[j].Mod(a[j], q)
				a[j+t].Sub(U, V)
				a[j+t].Mod(a[j+t], q)
			}
		}
	}
	return encodeNTTOutput(a), nil
}

func (c *nttForward) Name() string {
	return "NTT_FW"
}

// nttInverse implements the EIP-NTT NTT_INV precompile at address 0x0102.
// It performs the inverse NTT transformation using the Gentleman-Sande butterfly.
type nttInverse struct{}

func (c *nttInverse) RequiredGas(input []byte) uint64 {
	return params.NttInvGas
}

func (c *nttInverse) Run(input []byte) ([]byte, error) {
	q, n, err := parseNTTHeader(input)
	if err != nil {
		return nil, err
	}
	expectedLen := nttHeaderSize + int(n)*nttElementSize*2
	if len(input) != expectedLen {
		return nil, errNTTInvalidInputLength
	}

	a, err := parseNTTVector(input, nttHeaderSize, n, q)
	if err != nil {
		return nil, err
	}
	psiInvRev, err := parseNTTVector(input, nttHeaderSize+int(n)*nttElementSize, n, q)
	if err != nil {
		return nil, err
	}

	// Gentleman-Sande butterfly (in-place)
	U := new(big.Int)
	V := new(big.Int)

	t := uint64(1)
	for m := n; m > 1; m /= 2 {
		j1 := uint64(0)
		h := m / 2
		for i := uint64(0); i < h; i++ {
			j2 := j1 + t
			S := psiInvRev[h+i]
			for j := j1; j < j2; j++ {
				U.Set(a[j])
				V.Set(a[j+t])
				a[j].Add(U, V)
				a[j].Mod(a[j], q)
				a[j+t].Sub(U, V)
				a[j+t].Mul(a[j+t], S)
				a[j+t].Mod(a[j+t], q)
			}
			j1 += 2 * t
		}
		t *= 2
	}

	// Final scaling: a[j] = a[j] * n^{-1} mod q
	nBig := new(big.Int).SetUint64(n)
	nInv := new(big.Int).ModInverse(nBig, q)
	if nInv == nil {
		return nil, errNTTNoInverse
	}
	for j := uint64(0); j < n; j++ {
		a[j].Mul(a[j], nInv)
		a[j].Mod(a[j], q)
	}
	return encodeNTTOutput(a), nil
}

func (c *nttInverse) Name() string {
	return "NTT_INV"
}

// nttVecMulMod implements the EIP-NTT NTT_VECMULMOD precompile at address 0x0103.
// It performs element-wise modular multiplication of two vectors.
type nttVecMulMod struct{}

func (c *nttVecMulMod) RequiredGas(input []byte) uint64 {
	if len(input) < nttHeaderSize {
		return 0
	}
	q := new(big.Int).SetBytes(input[0:32])
	if q.Sign() <= 0 {
		return 0
	}
	nBig := new(big.Int).SetBytes(input[32:64])
	if !nBig.IsUint64() {
		return 0
	}
	n := nBig.Uint64()
	if n < 2 || (n&(n-1)) != 0 {
		return 0
	}
	k := nttComputeK(q)
	log2n := uint64(bits.TrailingZeros64(n))
	gas := k * log2n / 8
	if gas == 0 {
		gas = 1
	}
	return gas
}

func (c *nttVecMulMod) Run(input []byte) ([]byte, error) {
	q, n, err := parseNTTHeader(input)
	if err != nil {
		return nil, err
	}
	expectedLen := nttHeaderSize + int(n)*nttElementSize*2
	if len(input) != expectedLen {
		return nil, errNTTInvalidInputLength
	}

	a, err := parseNTTVector(input, nttHeaderSize, n, q)
	if err != nil {
		return nil, err
	}
	b, err := parseNTTVector(input, nttHeaderSize+int(n)*nttElementSize, n, q)
	if err != nil {
		return nil, err
	}

	result := make([]*big.Int, n)
	for i := uint64(0); i < n; i++ {
		result[i] = new(big.Int).Mul(a[i], b[i])
		result[i].Mod(result[i], q)
	}
	return encodeNTTOutput(result), nil
}

func (c *nttVecMulMod) Name() string {
	return "NTT_VECMULMOD"
}

// nttVecAddMod implements the EIP-NTT NTT_VECADDMOD precompile at address 0x0104.
// It performs element-wise modular addition of two vectors.
type nttVecAddMod struct{}

func (c *nttVecAddMod) RequiredGas(input []byte) uint64 {
	if len(input) < nttHeaderSize {
		return 0
	}
	q := new(big.Int).SetBytes(input[0:32])
	if q.Sign() <= 0 {
		return 0
	}
	nBig := new(big.Int).SetBytes(input[32:64])
	if !nBig.IsUint64() {
		return 0
	}
	n := nBig.Uint64()
	if n < 2 || (n&(n-1)) != 0 {
		return 0
	}
	k := nttComputeK(q)
	log2n := uint64(bits.TrailingZeros64(n))
	gas := k * log2n / 32
	if gas == 0 {
		gas = 1
	}
	return gas
}

func (c *nttVecAddMod) Run(input []byte) ([]byte, error) {
	q, n, err := parseNTTHeader(input)
	if err != nil {
		return nil, err
	}
	expectedLen := nttHeaderSize + int(n)*nttElementSize*2
	if len(input) != expectedLen {
		return nil, errNTTInvalidInputLength
	}

	a, err := parseNTTVector(input, nttHeaderSize, n, q)
	if err != nil {
		return nil, err
	}
	b, err := parseNTTVector(input, nttHeaderSize+int(n)*nttElementSize, n, q)
	if err != nil {
		return nil, err
	}

	result := make([]*big.Int, n)
	for i := uint64(0); i < n; i++ {
		result[i] = new(big.Int).Add(a[i], b[i])
		result[i].Mod(result[i], q)
	}
	return encodeNTTOutput(result), nil
}

func (c *nttVecAddMod) Name() string {
	return "NTT_VECADDMOD"
}

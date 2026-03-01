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
	"encoding/hex"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

func TestNttComputeK(t *testing.T) {
	tests := []struct {
		q    int64
		want uint64
	}{
		{12289, 16},      // FALCON: BitLen=14, ceil(log2)=14, next pow2=16
		{8380417, 32},    // DILITHIUM: BitLen=23, next pow2=32
		{3329, 16},       // KYBER: BitLen=12, next pow2=16
		{2013265921, 32}, // Babybear: BitLen=31, next pow2=32
		{17, 8},          // small prime: BitLen=5, next pow2=8
		{7, 4},           // small prime: BitLen=3, next pow2=4
		{3, 2},           // small prime: BitLen=2, next pow2=2
	}
	for _, tt := range tests {
		q := big.NewInt(tt.q)
		got := nttComputeK(q)
		if got != tt.want {
			t.Errorf("nttComputeK(%d) = %d, want %d", tt.q, got, tt.want)
		}
	}
}

// buildNTTInput constructs the precompile input bytes for NTT_FW/NTT_INV or VECMUL/VECADD.
// Format: [q (32B)][n (32B)][vec1 (n*32B)][vec2 (n*32B)]
func buildNTTInput(q *big.Int, n uint64, vec1, vec2 []*big.Int) []byte {
	input := make([]byte, 64+int(n)*32*2)
	qBytes := q.Bytes()
	copy(input[32-len(qBytes):32], qBytes)
	nBig := new(big.Int).SetUint64(n)
	nBytes := nBig.Bytes()
	copy(input[64-len(nBytes):64], nBytes)
	for i, v := range vec1 {
		b := v.Bytes()
		copy(input[64+i*32+(32-len(b)):64+(i+1)*32], b)
	}
	offset := 64 + int(n)*32
	for i, v := range vec2 {
		b := v.Bytes()
		copy(input[offset+i*32+(32-len(b)):offset+(i+1)*32], b)
	}
	return input
}

func TestNttVecAddMod(t *testing.T) {
	q := big.NewInt(7)
	n := uint64(4)
	a := []*big.Int{big.NewInt(3), big.NewInt(5), big.NewInt(6), big.NewInt(1)}
	b := []*big.Int{big.NewInt(5), big.NewInt(4), big.NewInt(3), big.NewInt(6)}
	expected := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(2), big.NewInt(0)}

	input := buildNTTInput(q, n, a, b)
	p := &nttVecAddMod{}
	gas := p.RequiredGas(input)
	res, _, err := RunPrecompiledContract(p, input, gas, nil)
	if err != nil {
		t.Fatal(err)
	}

	for i, exp := range expected {
		got := new(big.Int).SetBytes(res[i*32 : (i+1)*32])
		if got.Cmp(exp) != 0 {
			t.Errorf("VecAddMod[%d]: got %s, want %s", i, got, exp)
		}
	}
}

func TestNttVecMulMod(t *testing.T) {
	q := big.NewInt(12289)
	n := uint64(4)
	a := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)}
	b := []*big.Int{big.NewInt(5), big.NewInt(6), big.NewInt(7), big.NewInt(8)}
	expected := []*big.Int{big.NewInt(5), big.NewInt(12), big.NewInt(21), big.NewInt(32)}

	input := buildNTTInput(q, n, a, b)
	p := &nttVecMulMod{}
	gas := p.RequiredGas(input)
	res, _, err := RunPrecompiledContract(p, input, gas, nil)
	if err != nil {
		t.Fatal(err)
	}

	for i, exp := range expected {
		got := new(big.Int).SetBytes(res[i*32 : (i+1)*32])
		if got.Cmp(exp) != 0 {
			t.Errorf("VecMulMod[%d]: got %s, want %s", i, got, exp)
		}
	}
}

func TestNttVecMulModWrap(t *testing.T) {
	q := big.NewInt(7)
	n := uint64(4)
	a := []*big.Int{big.NewInt(5), big.NewInt(6), big.NewInt(3), big.NewInt(4)}
	b := []*big.Int{big.NewInt(3), big.NewInt(4), big.NewInt(5), big.NewInt(6)}
	// 5*3=15 mod 7=1, 6*4=24 mod 7=3, 3*5=15 mod 7=1, 4*6=24 mod 7=3
	expected := []*big.Int{big.NewInt(1), big.NewInt(3), big.NewInt(1), big.NewInt(3)}

	input := buildNTTInput(q, n, a, b)
	p := &nttVecMulMod{}
	gas := p.RequiredGas(input)
	res, _, err := RunPrecompiledContract(p, input, gas, nil)
	if err != nil {
		t.Fatal(err)
	}

	for i, exp := range expected {
		got := new(big.Int).SetBytes(res[i*32 : (i+1)*32])
		if got.Cmp(exp) != 0 {
			t.Errorf("VecMulMod[%d]: got %s, want %s", i, got, exp)
		}
	}
}

// TestNttForwardInverseRoundtrip tests NTT_FW followed by NTT_INV gives back the original.
// Uses q=17 (prime, 17 ≡ 1 mod 8 so n=4 works), n=4.
// ψ = 2 is a primitive 8th root of unity mod 17 (2^8 = 256 ≡ 256-15*17 = 256-255 = 1 mod 17).
func TestNttForwardInverseRoundtrip(t *testing.T) {
	q := big.NewInt(17)
	n := uint64(4)

	// ψ = 2 (primitive 2n=8th root of unity mod 17)
	// ψ^(-1) = 9 (since 2*9 = 18 ≡ 1 mod 17)
	//
	// For NTT_FW, we need Ψ_rev[n] = powers of ψ in bit-reversed order.
	// The table has n entries; indices [1..n-1] are used: Ψ_rev[m+i].
	// Standard NTT twiddle factors (bit-reversed):
	// Ψ_rev[0] = unused (placeholder 0)
	// Ψ_rev[1] = ψ^0 = 1
	// Ψ_rev[2] = ψ^0 = 1
	// Ψ_rev[3] = ψ^2 = 4
	//
	// More precisely, for negative-wrapped convolution NTT with n=4:
	// Level m=1: S = Ψ_rev[1] = ψ^1 = 2
	// Level m=2: S = Ψ_rev[2] = ψ^2 = 4, Ψ_rev[3] = ψ^(2+1) = ψ^3 = 8
	//
	// Wait, let me compute this properly.
	// For the "negative wrap convolution" NTT, the twiddle factors in
	// bit-reversed order are the powers of ψ (the 2n-th root of unity).
	//
	// The Ψ_rev table for n=4:
	// Index 1: ψ^(bit_rev(1, log2(n))) = ψ^(bit_rev(1, 2))
	// Actually, the standard approach:
	// Ψ_rev[i] for i in [0,n) stores ψ^(brv(i)) where brv is bit-reversal
	// of log2(n) bits.
	//
	// For n=4, log2(n)=2:
	// brv(0,2)=0, brv(1,2)=2, brv(2,2)=1, brv(3,2)=3
	// So: Ψ_rev[0]=ψ^0=1, Ψ_rev[1]=ψ^2=4, Ψ_rev[2]=ψ^1=2, Ψ_rev[3]=ψ^3=8

	psiRev := []*big.Int{
		big.NewInt(1), // index 0: ψ^0 = 1
		big.NewInt(4), // index 1: ψ^2 = 4
		big.NewInt(2), // index 2: ψ^1 = 2
		big.NewInt(8), // index 3: ψ^3 = 8
	}

	// For NTT_INV, Ψ^(-1)_rev[i] = (ψ^(-1))^(brv(i))
	// ψ^(-1) = 9 mod 17
	// 9^0=1, 9^1=9, 9^2=81 mod 17=81-4*17=81-68=13, 9^3=9*13=117 mod 17=117-6*17=117-102=15
	// brv order: [0]=9^0=1, [1]=9^2=13, [2]=9^1=9, [3]=9^3=15
	psiInvRev := []*big.Int{
		big.NewInt(1),  // index 0: (ψ^-1)^0 = 1
		big.NewInt(13), // index 1: (ψ^-1)^2 = 13
		big.NewInt(9),  // index 2: (ψ^-1)^1 = 9
		big.NewInt(15), // index 3: (ψ^-1)^3 = 15
	}

	// Original polynomial coefficients
	original := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)}

	// Step 1: Forward NTT
	fwInput := buildNTTInput(q, n, original, psiRev)
	fw := &nttForward{}
	fwGas := fw.RequiredGas(fwInput)
	fwResult, _, err := RunPrecompiledContract(fw, fwInput, fwGas, nil)
	if err != nil {
		t.Fatalf("NTT_FW failed: %v", err)
	}

	// Parse the forward result as a vector
	nttCoeffs := make([]*big.Int, n)
	for i := uint64(0); i < n; i++ {
		nttCoeffs[i] = new(big.Int).SetBytes(fwResult[i*32 : (i+1)*32])
	}

	// Step 2: Inverse NTT
	invInput := buildNTTInput(q, n, nttCoeffs, psiInvRev)
	inv := &nttInverse{}
	invGas := inv.RequiredGas(invInput)
	invResult, _, err := RunPrecompiledContract(inv, invInput, invGas, nil)
	if err != nil {
		t.Fatalf("NTT_INV failed: %v", err)
	}

	// Verify roundtrip
	for i := uint64(0); i < n; i++ {
		got := new(big.Int).SetBytes(invResult[i*32 : (i+1)*32])
		if got.Cmp(original[i]) != 0 {
			t.Errorf("Roundtrip[%d]: got %s, want %s", i, got, original[i])
		}
	}
}

// TestNttPolynomialMultiplication tests the full polynomial multiplication:
// f * g = NTT_INV(NTT_VECMULMOD(NTT_FW(f), NTT_FW(g)))
// using q=17, n=4.
func TestNttPolynomialMultiplication(t *testing.T) {
	q := big.NewInt(17)
	n := uint64(4)

	psiRev := []*big.Int{
		big.NewInt(1), big.NewInt(4), big.NewInt(2), big.NewInt(8),
	}
	psiInvRev := []*big.Int{
		big.NewInt(1), big.NewInt(13), big.NewInt(9), big.NewInt(15),
	}

	// f = 1 + 2x + 3x^2 + 4x^3
	f := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)}
	// g = 1 (constant polynomial)
	g := []*big.Int{big.NewInt(1), big.NewInt(0), big.NewInt(0), big.NewInt(0)}

	// NTT_FW(f)
	fwF := &nttForward{}
	fwFInput := buildNTTInput(q, n, f, psiRev)
	fwFResult, _, err := RunPrecompiledContract(fwF, fwFInput, fwF.RequiredGas(fwFInput), nil)
	if err != nil {
		t.Fatalf("NTT_FW(f) failed: %v", err)
	}

	// NTT_FW(g)
	fwG := &nttForward{}
	fwGInput := buildNTTInput(q, n, g, psiRev)
	fwGResult, _, err := RunPrecompiledContract(fwG, fwGInput, fwG.RequiredGas(fwGInput), nil)
	if err != nil {
		t.Fatalf("NTT_FW(g) failed: %v", err)
	}

	// Parse results
	nttF := make([]*big.Int, n)
	nttG := make([]*big.Int, n)
	for i := uint64(0); i < n; i++ {
		nttF[i] = new(big.Int).SetBytes(fwFResult[i*32 : (i+1)*32])
		nttG[i] = new(big.Int).SetBytes(fwGResult[i*32 : (i+1)*32])
	}

	// NTT_VECMULMOD(NTT_FW(f), NTT_FW(g))
	mul := &nttVecMulMod{}
	mulInput := buildNTTInput(q, n, nttF, nttG)
	mulResult, _, err := RunPrecompiledContract(mul, mulInput, mul.RequiredGas(mulInput), nil)
	if err != nil {
		t.Fatalf("VECMULMOD failed: %v", err)
	}

	// Parse product
	prod := make([]*big.Int, n)
	for i := uint64(0); i < n; i++ {
		prod[i] = new(big.Int).SetBytes(mulResult[i*32 : (i+1)*32])
	}

	// NTT_INV to get back to coefficient form
	inv := &nttInverse{}
	invInput := buildNTTInput(q, n, prod, psiInvRev)
	invResult, _, err := RunPrecompiledContract(inv, invInput, inv.RequiredGas(invInput), nil)
	if err != nil {
		t.Fatalf("NTT_INV failed: %v", err)
	}

	// f * 1 = f (in the ring Z_q[X]/(X^n+1))
	for i := uint64(0); i < n; i++ {
		got := new(big.Int).SetBytes(invResult[i*32 : (i+1)*32])
		if got.Cmp(f[i]) != 0 {
			t.Errorf("PolyMul[%d]: got %s, want %s", i, got, f[i])
		}
	}
}

// TestNttFailureCases tests error conditions.
func TestNttFailureCases(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		precomp   PrecompiledContract
		wantError string
	}{
		{
			name:      "empty input",
			input:     "",
			precomp:   &nttForward{},
			wantError: errNTTInvalidInputLength.Error(),
		},
		{
			name:      "too short header",
			input:     "0000000000000000000000000000000000000000000000000000000000000011",
			precomp:   &nttForward{},
			wantError: errNTTInvalidInputLength.Error(),
		},
		{
			name: "q = 0",
			// q=0, n=4
			input:     "0000000000000000000000000000000000000000000000000000000000000000" + "0000000000000000000000000000000000000000000000000000000000000004",
			precomp:   &nttForward{},
			wantError: errNTTModulusZero.Error(),
		},
		{
			name: "n not power of 2",
			// q=17, n=3
			input:     "0000000000000000000000000000000000000000000000000000000000000011" + "0000000000000000000000000000000000000000000000000000000000000003",
			precomp:   &nttForward{},
			wantError: errNTTInvalidDegree.Error(),
		},
		{
			name: "n = 1",
			// q=17, n=1
			input:     "0000000000000000000000000000000000000000000000000000000000000011" + "0000000000000000000000000000000000000000000000000000000000000001",
			precomp:   &nttForward{},
			wantError: errNTTInvalidDegree.Error(),
		},
		{
			name: "wrong input length (header only, missing vectors)",
			// q=17, n=4, but no vector data
			input:     "0000000000000000000000000000000000000000000000000000000000000011" + "0000000000000000000000000000000000000000000000000000000000000004",
			precomp:   &nttForward{},
			wantError: errNTTInvalidInputLength.Error(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := common.Hex2Bytes(tt.input)
			gas := tt.precomp.RequiredGas(in)
			if gas == 0 {
				gas = 1 // ensure we have enough gas to reach Run()
			}
			_, _, err := RunPrecompiledContract(tt.precomp, in, gas, nil)
			if err == nil {
				t.Fatalf("expected error %q, got nil", tt.wantError)
			}
			if err.Error() != tt.wantError {
				t.Errorf("expected error %q, got %q", tt.wantError, err.Error())
			}
		})
	}
}

// TestNttCoefficientTooLarge tests that coefficients >= q are rejected.
func TestNttCoefficientTooLarge(t *testing.T) {
	q := big.NewInt(7)
	n := uint64(2)
	// Coefficient 7 is not < 7
	a := []*big.Int{big.NewInt(7), big.NewInt(0)}
	b := []*big.Int{big.NewInt(0), big.NewInt(0)}

	input := buildNTTInput(q, n, a, b)
	p := &nttVecAddMod{}
	gas := p.RequiredGas(input)
	if gas == 0 {
		gas = 1
	}
	_, _, err := RunPrecompiledContract(p, input, gas, nil)
	if err == nil {
		t.Fatal("expected error for coefficient >= q")
	}
	if err.Error() != errNTTCoefficientTooLarge.Error() {
		t.Errorf("expected error %q, got %q", errNTTCoefficientTooLarge.Error(), err.Error())
	}
}

// TestNttGasCosts verifies gas calculation for VECMULMOD and VECADDMOD.
func TestNttGasCosts(t *testing.T) {
	// NTT_FW and NTT_INV: always 600
	fw := &nttForward{}
	inv := &nttInverse{}
	if fw.RequiredGas(nil) != 600 {
		t.Errorf("NTT_FW gas: got %d, want 600", fw.RequiredGas(nil))
	}
	if inv.RequiredGas(nil) != 600 {
		t.Errorf("NTT_INV gas: got %d, want 600", inv.RequiredGas(nil))
	}

	// VECMULMOD: k * log2(n) / 8
	// q=12289 (BitLen=14), k=16, n=4 (log2=2): 16*2/8 = 4
	q := big.NewInt(12289)
	n := uint64(4)
	input := buildNTTInput(q, n,
		[]*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
		[]*big.Int{big.NewInt(0), big.NewInt(0), big.NewInt(0), big.NewInt(0)},
	)
	mul := &nttVecMulMod{}
	if gas := mul.RequiredGas(input); gas != 4 {
		t.Errorf("VECMULMOD gas (q=12289, n=4): got %d, want 4", gas)
	}

	// VECADDMOD: k * log2(n) / 32
	// q=12289, k=16, n=4 (log2=2): 16*2/32 = 1
	add := &nttVecAddMod{}
	if gas := add.RequiredGas(input); gas != 1 {
		t.Errorf("VECADDMOD gas (q=12289, n=4): got %d, want 1", gas)
	}

	// Larger case: q=8380417 (DILITHIUM, BitLen=23), k=32, n=256 (log2=8)
	// VECMULMOD: 32*8/8 = 32
	// VECADDMOD: 32*8/32 = 8
	qDil := big.NewInt(8380417)
	nDil := uint64(256)
	bigInput := make([]byte, 64+int(nDil)*32*2)
	qDilBytes := qDil.Bytes()
	copy(bigInput[32-len(qDilBytes):32], qDilBytes)
	nDilBig := new(big.Int).SetUint64(nDil)
	nDilBytes := nDilBig.Bytes()
	copy(bigInput[64-len(nDilBytes):64], nDilBytes)

	mulDil := &nttVecMulMod{}
	if gas := mulDil.RequiredGas(bigInput); gas != 32 {
		t.Errorf("VECMULMOD gas (q=8380417, n=256): got %d, want 32", gas)
	}
	addDil := &nttVecAddMod{}
	if gas := addDil.RequiredGas(bigInput); gas != 8 {
		t.Errorf("VECADDMOD gas (q=8380417, n=256): got %d, want 8", gas)
	}
}

// TestNttOOG tests out-of-gas behavior.
func TestNttOOG(t *testing.T) {
	q := big.NewInt(17)
	n := uint64(4)
	a := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)}
	b := []*big.Int{big.NewInt(5), big.NewInt(6), big.NewInt(7), big.NewInt(8)}

	input := buildNTTInput(q, n, a, b)

	tests := []struct {
		name    string
		precomp PrecompiledContract
	}{
		{"NTT_FW", &nttForward{}},
		{"NTT_INV", &nttInverse{}},
		{"NTT_VECMULMOD", &nttVecMulMod{}},
		{"NTT_VECADDMOD", &nttVecAddMod{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gas := tt.precomp.RequiredGas(input)
			if gas == 0 {
				t.Skip("gas is 0, OOG test not applicable")
			}
			_, _, err := RunPrecompiledContract(tt.precomp, input, gas-1, nil)
			if err == nil || err.Error() != "out of gas" {
				t.Errorf("expected 'out of gas' error, got %v", err)
			}
		})
	}
}

// TestNttInputNotModified ensures precompile does not mutate input buffer.
func TestNttInputNotModified(t *testing.T) {
	q := big.NewInt(17)
	n := uint64(4)
	psiRev := []*big.Int{big.NewInt(1), big.NewInt(4), big.NewInt(2), big.NewInt(8)}
	a := []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)}

	input := buildNTTInput(q, n, a, psiRev)
	inputCopy := make([]byte, len(input))
	copy(inputCopy, input)

	fw := &nttForward{}
	gas := fw.RequiredGas(input)
	_, _, err := RunPrecompiledContract(fw, input, gas, nil)
	if err != nil {
		t.Fatal(err)
	}

	inputHex := hex.EncodeToString(input)
	copyHex := hex.EncodeToString(inputCopy)
	if inputHex != copyHex {
		t.Error("NTT_FW modified input data")
	}
}

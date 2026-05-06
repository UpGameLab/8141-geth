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
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
)

func TestFalconPrecompileGasAndName(t *testing.T) {
	tests := []struct {
		name string
		p    PrecompiledContract
		want string
		gas  uint64
	}{
		{
			name: "hash-to-point-shake256",
			p:    &falconHashToPointShake256{},
			want: "FALCON_HASH_TO_POINT_SHAKE256",
			gas:  params.FalconHashToPointGas,
		},
		{
			name: "hash-to-point-keccakprng",
			p:    &falconHashToPointKeccakPRNG{},
			want: "FALCON_HASH_TO_POINT_KECCAKPRNG",
			gas:  params.FalconHashToPointGas,
		},
		{
			name: "core",
			p:    &falconCore{},
			want: "FALCON_CORE",
			gas:  params.FalconCoreGas,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.RequiredGas(nil); got != tt.gas {
				t.Fatalf("unexpected gas: got %d want %d", got, tt.gas)
			}
			if got := tt.p.Name(); got != tt.want {
				t.Fatalf("unexpected name: got %s want %s", got, tt.want)
			}
		})
	}
}

func TestFalconHashToPointPrecompilesReturnChallenge(t *testing.T) {
	tests := []struct {
		name string
		p    PrecompiledContract
	}{
		{
			name: "hash-to-point-shake256",
			p:    &falconHashToPointShake256{},
		},
		{
			name: "hash-to-point-keccakprng",
			p:    &falconHashToPointKeccakPRNG{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ret, err := tt.p.Run(make([]byte, falconHashToPointInputSize))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(ret) != falconChallengeSize {
				t.Fatalf("unexpected challenge size: got %d want %d", len(ret), falconChallengeSize)
			}
			if !bytes.Equal(ret, make([]byte, falconChallengeSize)) {
				t.Fatalf("unexpected challenge value: got %x", ret)
			}
		})
	}
}

func TestFalconCorePrecompileReturnsTrue(t *testing.T) {
	ret, err := (&falconCore{}).Run(make([]byte, falconCoreInputSize))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(ret, true32Byte) {
		t.Fatalf("unexpected return value: got %x", ret)
	}
}

func TestFalconPrecompilesRejectInvalidInputLength(t *testing.T) {
	tests := []struct {
		name string
		p    PrecompiledContract
	}{
		{
			name: "hash-to-point-shake256",
			p:    &falconHashToPointShake256{},
		},
		{
			name: "hash-to-point-keccakprng",
			p:    &falconHashToPointKeccakPRNG{},
		},
		{
			name: "core",
			p:    &falconCore{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := tt.p.Run([]byte{0x01, 0x02, 0x03}); err == nil {
				t.Fatal("expected invalid input length error")
			}
		})
	}
}

func TestFalconPrecompileRegisteredInOsaka(t *testing.T) {
	tests := []struct {
		addr byte
		name string
	}{
		{addr: 0x14, name: "FALCON_HASH_TO_POINT_SHAKE256"},
		{addr: 0x15, name: "FALCON_HASH_TO_POINT_KECCAKPRNG"},
		{addr: 0x16, name: "FALCON_CORE"},
	}
	for _, tt := range tests {
		addr := common.BytesToAddress([]byte{tt.addr})
		p, ok := PrecompiledContractsOsaka[addr]
		if !ok {
			t.Fatalf("falcon precompile not registered at %#x", tt.addr)
		}
		if p.Name() != tt.name {
			t.Fatalf("unexpected precompile at %#x: got %s want %s", tt.addr, p.Name(), tt.name)
		}
	}
}

func TestFalconPrecompileExportedSet(t *testing.T) {
	tests := []struct {
		addr byte
		name string
	}{
		{addr: 0x14, name: "FALCON_HASH_TO_POINT_SHAKE256"},
		{addr: 0x15, name: "FALCON_HASH_TO_POINT_KECCAKPRNG"},
		{addr: 0x16, name: "FALCON_CORE"},
	}
	for _, tt := range tests {
		addr := common.BytesToAddress([]byte{tt.addr})
		p, ok := PrecompiledContractsFalcon[addr]
		if !ok {
			t.Fatalf("falcon precompile not exported at %#x", tt.addr)
		}
		if p.Name() != tt.name {
			t.Fatalf("unexpected exported precompile at %#x: got %s want %s", tt.addr, p.Name(), tt.name)
		}
	}
}

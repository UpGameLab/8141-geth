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
	}{
		{
			name: "shake256",
			p:    &verifyFalcon{},
			want: "VERIFY_FALCON",
		},
		{
			name: "keccak",
			p:    &verifyFalconEth{},
			want: "VERIFY_FALCON_ETH",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.p.RequiredGas(nil); got != params.VerifyFalconGas {
				t.Fatalf("unexpected gas: got %d want %d", got, params.VerifyFalconGas)
			}
			if got := tt.p.Name(); got != tt.want {
				t.Fatalf("unexpected name: got %s want %s", got, tt.want)
			}
		})
	}
}

func TestFalconPrecompileReturnsTrue(t *testing.T) {
	tests := []struct {
		name string
		p    PrecompiledContract
	}{
		{
			name: "shake256",
			p:    &verifyFalcon{},
		},
		{
			name: "keccak",
			p:    &verifyFalconEth{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ret, err := tt.p.Run([]byte{0x01, 0x02, 0x03})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !bytes.Equal(ret, true32Byte) {
				t.Fatalf("unexpected return value: got %x", ret)
			}
		})
	}
}

func TestFalconPrecompileRegisteredInOsaka(t *testing.T) {
	tests := []struct {
		addr byte
		name string
	}{
		{addr: 0x14, name: "VERIFY_FALCON"},
		{addr: 0x15, name: "VERIFY_FALCON_ETH"},
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
		{addr: 0x14, name: "VERIFY_FALCON"},
		{addr: 0x15, name: "VERIFY_FALCON_ETH"},
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

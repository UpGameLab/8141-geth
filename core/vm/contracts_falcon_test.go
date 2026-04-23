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
	p := &verifyFalcon{}
	if got := p.RequiredGas(nil); got != params.VerifyFalconGas {
		t.Fatalf("unexpected gas: got %d want %d", got, params.VerifyFalconGas)
	}
	if got := p.Name(); got != "VERIFY_FALCON" {
		t.Fatalf("unexpected name: got %s", got)
	}
}

func TestFalconPrecompileReturnsTrue(t *testing.T) {
	p := &verifyFalcon{}
	ret, err := p.Run([]byte{0x01, 0x02, 0x03})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(ret, true32Byte) {
		t.Fatalf("unexpected return value: got %x", ret)
	}
}

func TestFalconPrecompileRegisteredInOsaka(t *testing.T) {
	addr := common.BytesToAddress([]byte{0x14})
	p, ok := PrecompiledContractsOsaka[addr]
	if !ok {
		t.Fatalf("falcon precompile not registered at 0x14")
	}
	if p.Name() != "VERIFY_FALCON" {
		t.Fatalf("unexpected precompile at 0x14: %s", p.Name())
	}
}

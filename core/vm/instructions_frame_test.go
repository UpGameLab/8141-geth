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
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/holiman/uint256"
)

func newFrameParamTestEVM() (*EVM, common.Address, common.Address) {
	sender := common.HexToAddress("0x1111111111111111111111111111111111111111")
	target := common.HexToAddress("0x2222222222222222222222222222222222222222")
	return &EVM{
		FrameCtx: &FrameContext{
			Sender: sender,
			Nonce:  99,
			Frames: []types.Frame{
				{
					Mode:     types.FrameModeDefault,
					Target:   nil,
					GasLimit: 111,
					Value:    nil,
				},
				{
					Mode:     types.FrameModeSender,
					Flags:    0x07,
					Target:   &target,
					GasLimit: 222,
					Value:    uint256.NewInt(333),
					Data:     []byte{0xaa, 0xbb, 0xcc},
				},
			},
			FrameIndex:   2,
			FrameResults: []uint8{ApproveExecution, ApproveBoth},
		},
	}, sender, target
}

func TestGetFrameParam(t *testing.T) {
	evm, sender, target := newFrameParamTestEVM()

	tests := []struct {
		name     string
		selector uint64
		want     *uint256.Int
	}{
		{"gas", frameParamGas, uint256.NewInt(222)},
		{"mode", frameParamMode, uint256.NewInt(uint64(types.FrameModeSender))},
		{"flags", frameParamFlags, uint256.NewInt(0x07)},
		{"data length", frameParamDataLen, uint256.NewInt(3)},
		{"status", frameParamStatus, uint256.NewInt(uint64(ApproveBoth))},
		{"allowed scope", frameParamAllowedScope, uint256.NewInt(0x03)},
		{"atomic batch", frameParamAtomicBatch, uint256.NewInt(1)},
		{"value", frameParamValue, uint256.NewInt(333)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := getFrameParam(evm, test.selector, 1, FRAMEPARAM)
			if err != nil {
				t.Fatal(err)
			}
			if value := new(uint256.Int).SetBytes(got); !value.Eq(test.want) {
				t.Fatalf("got %v, want %v", value, test.want)
			}
		})
	}

	gotTarget, err := getFrameParam(evm, frameParamTarget, 1, FRAMEPARAM)
	if err != nil {
		t.Fatal(err)
	}
	if want := common.LeftPadBytes(target.Bytes(), 32); !bytes.Equal(gotTarget, want) {
		t.Fatalf("target: got %x, want %x", gotTarget, want)
	}

	gotSender, err := getFrameParam(evm, frameParamTarget, 0, FRAMEPARAM)
	if err != nil {
		t.Fatal(err)
	}
	if want := common.LeftPadBytes(sender.Bytes(), 32); !bytes.Equal(gotSender, want) {
		t.Fatalf("nil target: got %x, want sender %x", gotSender, want)
	}

	gotValue, err := getFrameParam(evm, frameParamValue, 0, FRAMEPARAM)
	if err != nil {
		t.Fatal(err)
	}
	if value := new(uint256.Int).SetBytes(gotValue); !value.IsZero() {
		t.Fatalf("nil value: got %v, want 0", value)
	}

	gotAtomic, err := getFrameParam(evm, frameParamAtomicBatch, 0, FRAMEPARAM)
	if err != nil {
		t.Fatal(err)
	}
	if value := new(uint256.Int).SetBytes(gotAtomic); !value.IsZero() {
		t.Fatalf("unset atomic batch: got %v, want 0", value)
	}
}

func TestGetFrameParamErrors(t *testing.T) {
	evm, _, _ := newFrameParamTestEVM()

	tests := []struct {
		name     string
		evm      *EVM
		selector uint64
		index    uint64
	}{
		{"no frame context", new(EVM), frameParamTarget, 0},
		{"invalid index", evm, frameParamTarget, 2},
		{"invalid selector", evm, frameParamValue + 1, 0},
		{"current frame status", evm, frameParamStatus, 1},
	}
	evm.FrameCtx.FrameIndex = 1

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := getFrameParam(test.evm, test.selector, test.index, FRAMEPARAM); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestGetTxParamFrameCompatibilitySelectors(t *testing.T) {
	evm, _, _ := newFrameParamTestEVM()

	for selector := uint64(frameParamTarget); selector <= frameParamValue; selector++ {
		want, err := getFrameParam(evm, selector, 1, TXPARAMLOAD)
		if err != nil {
			t.Fatal(err)
		}
		got, err := getTxParam(evm, selector, 1)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("selector %#x: got %x, want %x", selector, got, want)
		}
	}

	got, err := getTxParam(evm, txParamNonce, 0)
	if err != nil {
		t.Fatal(err)
	}
	if value := new(uint256.Int).SetBytes(got); value.Uint64() != 99 {
		t.Fatalf("transaction nonce: got %v, want 99", value)
	}
}

func TestOpTxParamLoadUsesCompilerStackShape(t *testing.T) {
	evm, _, _ := newFrameParamTestEVM()
	evm.FrameCtx.SigHash = common.HexToHash("0x1234")
	stack := newstack()
	defer returnStack(stack)
	scope := &ScopeContext{Stack: stack}

	stack.push(uint256.NewInt(txParamSigHash))
	if _, err := opTxParamLoad(new(uint64), evm, scope); err != nil {
		t.Fatal(err)
	}
	if stack.len() != 1 {
		t.Fatalf("stack length: got %d, want 1", stack.len())
	}
	if value := stack.pop(); value.Bytes32() != evm.FrameCtx.SigHash {
		t.Fatalf("sig hash: got %x, want %x", value.Bytes32(), evm.FrameCtx.SigHash)
	}

	stack.push(uint256.NewInt(txParamCurrentFrame))
	if _, err := opTxParamLoad(new(uint64), evm, scope); err != nil {
		t.Fatal(err)
	}
	if value := stack.pop(); value.Uint64() != uint64(evm.FrameCtx.FrameIndex) {
		t.Fatalf("current frame: got %v, want %d", &value, evm.FrameCtx.FrameIndex)
	}
}

func TestOpFrameParamSupportsFrameZero(t *testing.T) {
	evm, _, _ := newFrameParamTestEVM()
	if op := newPragueInstructionSet()[FRAMEPARAM]; op == nil || op.undefined || op.execute == nil {
		t.Fatal("FRAMEPARAM opcode is not registered")
	}
	stack := newstack()
	defer returnStack(stack)

	stack.push(uint256.NewInt(0))
	stack.push(uint256.NewInt(frameParamGas))
	scope := &ScopeContext{Stack: stack}
	if _, err := opFrameParam(new(uint64), evm, scope); err != nil {
		t.Fatal(err)
	}
	if stack.len() != 1 {
		t.Fatalf("stack length: got %d, want 1", stack.len())
	}
	if value := stack.pop(); value.Uint64() != 111 {
		t.Fatalf("frame zero gas: got %v, want 111", &value)
	}
}

func TestOpcodeRegistration(t *testing.T) {
	for name, jumpTable := range map[string]JumpTable{
		"Prague": newPragueInstructionSet(),
		"Osaka":  newOsakaInstructionSet(),
	} {
		t.Run(name, func(t *testing.T) {
			for _, opcode := range []OpCode{TXPARAMLOAD, FRAMEPARAM} {
				op := jumpTable[opcode]
				if op == nil || op.undefined || op.execute == nil {
					t.Fatalf("%s is not registered", opcode)
				}
			}
			if op := jumpTable[TXPARAMLOAD]; op.minStack != minStack(1, 1) || op.maxStack != maxStack(1, 1) {
				t.Fatal("TXPARAMLOAD does not use the compiler's one-input stack shape")
			}
		})
	}
}

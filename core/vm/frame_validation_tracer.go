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
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/tracing"
)

// FrameValidationError represents a specific ERC-7562 rule violation detected
// during VERIFY frame simulation.
type FrameValidationError struct {
	Rule    string // e.g. "OP-011", "OP-012"
	Message string
}

func (e *FrameValidationError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Rule, e.Message)
}

// bannedOpcodes is the set of opcodes forbidden in VERIFY frames per ERC-7562 [OP-011].
// Note: SSTORE, LOG0-4, CALL with value are already blocked by STATICCALL/readOnly.
var bannedOpcodes = map[OpCode]bool{
	ORIGIN:       true, // 0x32
	GASPRICE:     true, // 0x3a
	BLOCKHASH:    true, // 0x40
	COINBASE:     true, // 0x41
	TIMESTAMP:    true, // 0x42
	NUMBER:       true, // 0x43
	PREVRANDAO:   true, // 0x44 (same as DIFFICULTY)
	GASLIMIT:     true, // 0x45
	BASEFEE:      true, // 0x48
	BLOBHASH:     true, // 0x49
	BLOBBASEFEE:  true, // 0x4a
	CREATE:       true, // 0xf0
	CREATE2:      true, // 0xf5
	SELFDESTRUCT: true, // 0xff
	INVALID:      true, // 0xfe [OP-011]
	BALANCE:      true, // 0x31 [OP-080]
	SELFBALANCE:  true, // 0x47 [OP-080]
}

// FrameValidationTracer checks ERC-7562-style rules during VERIFY frame simulation.
// It is designed to be lightweight and fail-fast: it records the first violation
// and short-circuits all subsequent hooks.
type FrameValidationTracer struct {
	stateDB     StateDB            // For GetCodeSize checks (OP-041)
	sender      common.Address     // tx.sender — exempt from OP-041
	precompiles map[common.Address]bool

	lastOp      OpCode // Previous opcode for GAS rule (OP-012)
	lastOpValid bool   // Whether lastOp is meaningful

	violation *FrameValidationError // First violation (nil = no violation)
}

// NewFrameValidationTracer creates a tracer for VERIFY frame validation.
func NewFrameValidationTracer(stateDB StateDB, sender common.Address, precompiles []common.Address) *FrameValidationTracer {
	pm := make(map[common.Address]bool, len(precompiles))
	for _, addr := range precompiles {
		pm[addr] = true
	}
	return &FrameValidationTracer{
		stateDB:     stateDB,
		sender:      sender,
		precompiles: pm,
	}
}

// Violation returns the first detected rule violation, or nil.
func (t *FrameValidationTracer) Violation() *FrameValidationError {
	return t.violation
}

// Hooks returns the tracing hooks to attach to EVM Config.Tracer.
func (t *FrameValidationTracer) Hooks() *tracing.Hooks {
	return &tracing.Hooks{
		OnOpcode: t.OnOpcode,
		OnEnter:  t.OnEnter,
		OnExit:   t.OnExit,
	}
}

// OnOpcode is called before each opcode execution.
func (t *FrameValidationTracer) OnOpcode(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
	if t.violation != nil {
		return
	}
	opcode := OpCode(op)

	// Reset lastOp tracking on RETURN/REVERT BEFORE checking OP-012.
	// This matches the erc7562 tracer pattern (erc7562.go:396-400):
	// GAS→RETURN is valid since RETURN ends the call frame.
	if opcode == RETURN || opcode == REVERT {
		t.lastOpValid = false
	}

	// [OP-012] Check if previous opcode was GAS not followed by CALL.
	if t.lastOpValid && t.lastOp == GAS && !isCallOp(opcode) {
		t.violation = &FrameValidationError{
			Rule:    "OP-012",
			Message: fmt.Sprintf("GAS opcode not followed by CALL (followed by %s at pc=%d depth=%d)", opcode, pc, depth),
		}
		return
	}

	// [OP-011, OP-080] Check banned opcodes.
	if bannedOpcodes[opcode] {
		rule := "OP-011"
		if opcode == BALANCE || opcode == SELFBALANCE {
			rule = "OP-080"
		}
		t.violation = &FrameValidationError{
			Rule:    rule,
			Message: fmt.Sprintf("banned opcode %s at pc=%d depth=%d", opcode, pc, depth),
		}
		return
	}

	// [OP-041] EXTCODE/CALL targets must have deployed code.
	if isExtOrCallOp(opcode) && scope != nil {
		stackData := scope.StackData()
		addrIdx := 0
		if isCallOp(opcode) {
			addrIdx = 1 // CALL-type: address is stack[1] (after gas argument)
		}
		if len(stackData) > addrIdx {
			addr := common.BytesToAddress(stackData[len(stackData)-addrIdx-1].Bytes())
			// Skip precompiles and sender (OP-042 exception).
			if !t.precompiles[addr] && addr != t.sender {
				if t.stateDB.GetCodeSize(addr) == 0 {
					t.violation = &FrameValidationError{
						Rule:    "OP-041",
						Message: fmt.Sprintf("%s target %s has no code at pc=%d depth=%d", opcode, addr.Hex(), pc, depth),
					}
					return
				}
			}
		}
	}

	// Track lastOp for OP-012 (RETURN/REVERT already handled above).
	if opcode != RETURN && opcode != REVERT {
		t.lastOp = opcode
		t.lastOpValid = true
	}
}

// OnEnter is called when EVM enters a new call scope.
func (t *FrameValidationTracer) OnEnter(depth int, typ byte, from common.Address, to common.Address, input []byte, gas uint64, value *big.Int) {
	// No additional checks needed beyond what OnOpcode handles.
}

// OnExit is called when EVM exits a call scope.
func (t *FrameValidationTracer) OnExit(depth int, output []byte, gasUsed uint64, err error, reverted bool) {
	if t.violation != nil {
		return
	}
	// [OP-020] Out-of-gas revert is forbidden — prevents gas limit probing.
	if errors.Is(err, ErrOutOfGas) || errors.Is(err, ErrCodeStoreOutOfGas) {
		t.violation = &FrameValidationError{
			Rule:    "OP-020",
			Message: "out-of-gas during VERIFY frame execution",
		}
	}
}

func isCallOp(op OpCode) bool {
	return op == CALL || op == CALLCODE || op == DELEGATECALL || op == STATICCALL
}

func isExtOp(op OpCode) bool {
	return op == EXTCODECOPY || op == EXTCODESIZE || op == EXTCODEHASH
}

func isExtOrCallOp(op OpCode) bool {
	return isExtOp(op) || isCallOp(op)
}

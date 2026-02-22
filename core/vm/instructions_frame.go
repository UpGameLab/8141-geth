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
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// Approval status codes as returned by APPROVE and observable via call status.
const (
	ApproveNone      uint8 = 0 // No approval (normal RETURN or not set).
	ApproveExecution uint8 = 2 // APPROVE(0x0): sender approved execution.
	ApprovePayment   uint8 = 3 // APPROVE(0x1): payer approved payment.
	ApproveBoth      uint8 = 4 // APPROVE(0x2): both execution and payment.
)

// FrameContext holds the context for executing a frame transaction (EIP-8141).
// It is set on the EVM when processing a frame transaction and provides data
// needed by the TXPARAM* opcodes. All fields are populated from the flattened
// Message during executeFrames().
type FrameContext struct {
	Sender       common.Address  // tx.sender
	Nonce        uint64          // tx.nonce
	Frames       []types.Frame   // tx.frames
	GasTipCap    *uint256.Int    // max_priority_fee_per_gas
	GasFeeCap    *uint256.Int    // max_fee_per_gas
	BlobFeeCap   *uint256.Int    // max_fee_per_blob_gas
	BlobHashes   []common.Hash   // blob_versioned_hashes
	GasLimit     uint64          // Total gas limit (intrinsic + calldata + sum(frame.gas_limit))
	SigHash      common.Hash     // Cached compute_sig_hash(tx).
	FrameIndex   int             // Currently executing frame index.
	FrameResults []uint8         // Status of each completed frame (0=fail, 1=success, 2-4=approve).
}

// opApprove implements the APPROVE opcode (0xaa) as defined in EIP-8141.
// It behaves like RETURN but with an additional scope operand that signals
// approval status.
//
// Per EIP-8141, APPROVE enforces:
//   - Must be in a frame tx context (FrameCtx != nil).
//   - ADDRESS == frame.target: only the frame target contract can call APPROVE.
//     This prevents subcalls from issuing approvals. DELEGATECALL preserves
//     ADDRESS, so delegate patterns still work.
//   - Scope 0x0/0x2 (execution approval): frame.target must equal tx.sender,
//     since only the sender contract can approve execution.
//
// Stack: [offset, length, scope]
func opApprove(pc *uint64, evm *EVM, scope *ScopeContext) ([]byte, error) {
	offset, size := scope.Stack.pop(), scope.Stack.pop()
	scopeVal := scope.Stack.pop()

	// Validate scope: must be 0, 1, or 2.
	s := scopeVal.Uint64()
	if s > 2 {
		return nil, &ErrInvalidOpCode{opcode: APPROVE}
	}

	// Must be in a frame tx context.
	if evm.FrameCtx == nil {
		return nil, &ErrInvalidOpCode{opcode: APPROVE}
	}

	// ADDRESS == frame.target: only the frame target can call APPROVE.
	currentFrame := evm.FrameCtx.Frames[evm.FrameCtx.FrameIndex]
	frameTarget := evm.FrameCtx.Sender
	if currentFrame.Target != nil {
		frameTarget = *currentFrame.Target
	}
	if scope.Contract.Address() != frameTarget {
		return nil, &ErrInvalidOpCode{opcode: APPROVE}
	}

	// Scope 0x0/0x2 (execution approval): frame.target must be tx.sender.
	if (s == 0 || s == 2) && frameTarget != evm.FrameCtx.Sender {
		return nil, &ErrInvalidOpCode{opcode: APPROVE}
	}

	// Map scope operand to approval status code: scope + 2.
	evm.ApproveScope = uint8(s) + 2

	ret := scope.Memory.GetCopy(offset.Uint64(), size.Uint64())
	return ret, errStopToken
}

// TXPARAM parameter selectors.
const (
	txParamTxType       = 0x00
	txParamNonce        = 0x01
	txParamSender       = 0x02
	txParamGasTipCap    = 0x03
	txParamGasFeeCap    = 0x04
	txParamBlobFeeCap   = 0x05
	txParamMaxCost      = 0x06
	txParamBlobHashLen  = 0x07
	txParamSigHash      = 0x08
	txParamFrameCount   = 0x09
	txParamFrameIdx     = 0x10
	txParamFrameTarget  = 0x11
	txParamFrameData    = 0x12
	txParamFrameGas     = 0x13
	txParamFrameMode    = 0x14
	txParamFrameStatus  = 0x15
)

// bytes32 converts a uint256 to a []byte slice via its Bytes32() method.
func bytes32(v *uint256.Int) []byte {
	b := v.Bytes32()
	return b[:]
}

// getTxParam returns the byte slice for the given tx parameter.
// For fixed 32-byte params, it returns a 32-byte big-endian value.
// For dynamic params (frame data), it returns the raw bytes.
func getTxParam(evm *EVM, in1, in2 uint64) ([]byte, error) {
	fc := evm.FrameCtx
	if fc == nil {
		return nil, ErrWriteProtection // Not in a frame tx context.
	}

	// Per EIP-8141, in2 must be 0 for non-frame-indexed parameters (0x00-0x10).
	// Frame-indexed parameters (0x11-0x15) use in2 as the frame index.
	isFrameIndexed := in1 >= txParamFrameTarget && in1 <= txParamFrameStatus
	if !isFrameIndexed && in2 != 0 {
		return nil, &ErrInvalidOpCode{opcode: TXPARAMLOAD}
	}

	switch in1 {
	case txParamTxType:
		v := new(uint256.Int).SetUint64(uint64(types.FrameTxType))
		return bytes32(v), nil

	case txParamNonce:
		v := new(uint256.Int).SetUint64(fc.Nonce)
		return bytes32(v), nil

	case txParamSender:
		var buf [32]byte
		copy(buf[12:], fc.Sender[:])
		return buf[:], nil

	case txParamGasTipCap:
		v := new(uint256.Int)
		if fc.GasTipCap != nil {
			v.Set(fc.GasTipCap)
		}
		return bytes32(v), nil

	case txParamGasFeeCap:
		v := new(uint256.Int)
		if fc.GasFeeCap != nil {
			v.Set(fc.GasFeeCap)
		}
		return bytes32(v), nil

	case txParamBlobFeeCap:
		v := new(uint256.Int)
		if fc.BlobFeeCap != nil {
			v.Set(fc.BlobFeeCap)
		}
		return bytes32(v), nil

	case txParamMaxCost:
		// max cost = tx_gas_limit * max_fee_per_gas + blob_fees
		gasLimit := new(uint256.Int).SetUint64(fc.GasLimit)
		maxCost := new(uint256.Int).Mul(gasLimit, fc.GasFeeCap)
		// Add blob cost: len(blob_hashes) * GAS_PER_BLOB * blob_fee_cap
		if len(fc.BlobHashes) > 0 && fc.BlobFeeCap != nil {
			blobGas := new(uint256.Int).SetUint64(params.BlobTxBlobGasPerBlob * uint64(len(fc.BlobHashes)))
			blobCost := new(uint256.Int).Mul(blobGas, fc.BlobFeeCap)
			maxCost.Add(maxCost, blobCost)
		}
		return bytes32(maxCost), nil

	case txParamBlobHashLen:
		v := new(uint256.Int).SetUint64(uint64(len(fc.BlobHashes)))
		return bytes32(v), nil

	case txParamSigHash:
		return fc.SigHash[:], nil

	case txParamFrameCount:
		v := new(uint256.Int).SetUint64(uint64(len(fc.Frames)))
		return bytes32(v), nil

	case txParamFrameIdx:
		v := new(uint256.Int).SetUint64(uint64(fc.FrameIndex))
		return bytes32(v), nil

	case txParamFrameTarget:
		if in2 >= uint64(len(fc.Frames)) {
			return nil, &ErrInvalidOpCode{opcode: TXPARAMLOAD}
		}
		idx := int(in2)
		var buf [32]byte
		f := &fc.Frames[idx]
		if f.Target != nil {
			copy(buf[12:], f.Target[:])
		} else {
			copy(buf[12:], fc.Sender[:])
		}
		return buf[:], nil

	case txParamFrameData:
		if in2 >= uint64(len(fc.Frames)) {
			return nil, &ErrInvalidOpCode{opcode: TXPARAMLOAD}
		}
		idx := int(in2)
		f := &fc.Frames[idx]
		// VERIFY frames return empty data.
		if f.Mode == types.FrameModeVerify {
			return nil, nil
		}
		return f.Data, nil

	case txParamFrameGas:
		if in2 >= uint64(len(fc.Frames)) {
			return nil, &ErrInvalidOpCode{opcode: TXPARAMLOAD}
		}
		v := new(uint256.Int).SetUint64(fc.Frames[int(in2)].GasLimit)
		return bytes32(v), nil

	case txParamFrameMode:
		if in2 >= uint64(len(fc.Frames)) {
			return nil, &ErrInvalidOpCode{opcode: TXPARAMLOAD}
		}
		v := new(uint256.Int).SetUint64(uint64(fc.Frames[int(in2)].Mode))
		return bytes32(v), nil

	case txParamFrameStatus:
		if in2 >= uint64(len(fc.Frames)) {
			return nil, &ErrInvalidOpCode{opcode: TXPARAMLOAD}
		}
		idx := int(in2)
		// Cannot query current or future frame status.
		if idx >= fc.FrameIndex {
			return nil, &ErrInvalidOpCode{opcode: TXPARAMLOAD}
		}
		v := new(uint256.Int).SetUint64(uint64(fc.FrameResults[idx]))
		return bytes32(v), nil

	default:
		return nil, &ErrInvalidOpCode{opcode: TXPARAMLOAD}
	}
}

// opTxParamLoad implements TXPARAMLOAD (0xb0).
// Stack: [in1, in2, offset] → [value]
func opTxParamLoad(pc *uint64, evm *EVM, scope *ScopeContext) ([]byte, error) {
	in1 := scope.Stack.pop()
	in2 := scope.Stack.pop()
	offset := scope.Stack.peek()

	data, err := getTxParam(evm, in1.Uint64(), in2.Uint64())
	if err != nil {
		return nil, err
	}

	off := int(offset.Uint64())
	var word [32]byte
	if off < len(data) {
		end := off + 32
		if end > len(data) {
			end = len(data)
		}
		copy(word[:], data[off:end])
	}
	offset.SetBytes32(word[:])
	return nil, nil
}

// opTxParamSize implements TXPARAMSIZE (0xb1).
// Stack: [in1, in2] → [size]
func opTxParamSize(pc *uint64, evm *EVM, scope *ScopeContext) ([]byte, error) {
	in1 := scope.Stack.pop()
	in2 := scope.Stack.peek()

	data, err := getTxParam(evm, in1.Uint64(), in2.Uint64())
	if err != nil {
		return nil, err
	}

	in2.SetUint64(uint64(len(data)))
	return nil, nil
}

// opTxParamCopy implements TXPARAMCOPY (0xb2).
// Stack: [in1, in2, destOffset, offset, size]
func opTxParamCopy(pc *uint64, evm *EVM, scope *ScopeContext) ([]byte, error) {
	in1 := scope.Stack.pop()
	in2 := scope.Stack.pop()
	memOffset := scope.Stack.pop()
	dataOffset := scope.Stack.pop()
	length := scope.Stack.pop()

	data, err := getTxParam(evm, in1.Uint64(), in2.Uint64())
	if err != nil {
		return nil, err
	}

	dataOff64 := dataOffset.Uint64()
	len64 := length.Uint64()

	// Build the padded copy. Guard against dataOff64+len64 overflowing uint64.
	var end uint64
	if dataOff64 > ^uint64(0)-len64 {
		end = uint64(len(data))
	} else {
		end = dataOff64 + len64
		if end > uint64(len(data)) {
			end = uint64(len(data))
		}
	}
	var padded []byte
	if dataOff64 < uint64(len(data)) {
		padded = common.RightPadBytes(data[dataOff64:end], int(len64))
	} else {
		padded = make([]byte, len64)
	}

	scope.Memory.Set(memOffset.Uint64(), len64, padded)
	return nil, nil
}

// memoryTxParamCopy returns the memory size required for TXPARAMCOPY.
// Stack layout: [in1, in2, destOffset, offset, size]
// destOffset is at Back(2), size at Back(4).
func memoryTxParamCopy(stack *Stack) (uint64, bool) {
	return calcMemSize64(stack.Back(2), stack.Back(4))
}

// gasTxParamCopy calculates dynamic gas for TXPARAMCOPY.
// Stack layout: [in1, in2, destOffset, offset, size] — size is Back(4).
func gasTxParamCopy(evm *EVM, contract *Contract, stack *Stack, mem *Memory, memorySize uint64) (uint64, error) {
	gas, err := memoryGasCost(mem, memorySize)
	if err != nil {
		return 0, err
	}
	words, overflow := stack.Back(4).Uint64WithOverflow()
	if overflow {
		return 0, ErrGasUintOverflow
	}
	if words, overflow = math.SafeMul(toWordSize(words), params.CopyGas); overflow {
		return 0, ErrGasUintOverflow
	}
	if gas, overflow = math.SafeAdd(gas, words); overflow {
		return 0, ErrGasUintOverflow
	}
	return gas, nil
}

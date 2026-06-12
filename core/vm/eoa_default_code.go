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
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/secp256r1"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

// Signature types for EOA default code.
const (
	sigTypeSecp256k1 = 0x00
	sigTypeP256      = 0x01
	sigTypeFalcon    = 0x04
	sigTypeFalconEth = 0x05
)

const (
	currentFalconEOAInputSize = 1 + falconPKSize + falconSigSize
)

// Gas costs for EOA default code operations.
const (
	// defaultCodeBaseGas is the base gas cost for default code execution.
	defaultCodeBaseGas uint64 = 100
)

// eoaCallRLP is the RLP-decodable form for calls in SENDER mode default code.
type eoaCallRLP struct {
	Target common.Address
	Value  *big.Int
	Data   []byte
}

// ExecuteDefaultCode implements the EIP-8141 "default code" behavior for EOAs
// (accounts with no code) when they are the target of a frame transaction.
//
// The function is called from executeFrames() when the frame target has no code.
// It interprets frame.data according to the frame mode and performs the
// appropriate action (signature verification, call execution, or revert).
//
// Returns the return data, leftover gas, and any error.
func ExecuteDefaultCode(evm *EVM, caller common.Address, target common.Address, input []byte, gas uint64, frameMode uint8) ([]byte, uint64, error) {
	if len(input) == 0 {
		return nil, gas, ErrExecutionReverted
	}

	// Current frame transactions carry mode and APPROVE scope in the frame
	// fields. Keep accepting the legacy embedded header for older clients and
	// the existing Falcon EOA encoding.
	if frameMode == types.FrameModeVerify && isCurrentEOAVerifyInput(input) {
		scope, ok := currentFrameApproveScope(evm)
		if !ok {
			return nil, gas, ErrExecutionReverted
		}
		return executeDefaultVerify(evm, target, input, gas, scope, true)
	}

	firstByte := input[0]
	scope := (firstByte >> 4) & 0x0F // high nibble: APPROVE scope
	dataMode := firstByte & 0x0F     // low nibble: operation mode

	switch dataMode {
	case types.FrameModeVerify:
		return executeDefaultVerify(evm, target, input, gas, scope, false)
	case types.FrameModeSender:
		return executeDefaultSender(evm, target, input, gas, scope)
	case types.FrameModeDefault:
		return nil, gas, ErrExecutionReverted
	default:
		return nil, gas, ErrExecutionReverted
	}
}

func isCurrentEOAVerifyInput(input []byte) bool {
	switch input[0] {
	case sigTypeSecp256k1:
		return len(input) == 1+65
	case sigTypeP256:
		return len(input) == 1+128
	case sigTypeFalcon, sigTypeFalconEth:
		return len(input) == currentFalconEOAInputSize
	default:
		return false
	}
}

func currentFrameApproveScope(evm *EVM) (uint8, bool) {
	fc := evm.FrameCtx
	if fc == nil || fc.FrameIndex < 0 || fc.FrameIndex >= len(fc.Frames) {
		return 0, false
	}
	return fc.Frames[fc.FrameIndex].Flags & frameParamApproveScopeMask, true
}

// executeDefaultVerify implements the VERIFY mode of the EOA default code.
// It verifies a signature (secp256k1 or P256) against the transaction's
// signature hash and calls APPROVE on success.
func executeDefaultVerify(evm *EVM, target common.Address, input []byte, gas uint64, scope uint8, current bool) ([]byte, uint64, error) {
	fc := evm.FrameCtx
	if fc == nil {
		return nil, gas, ErrExecutionReverted
	}

	// frame.target must equal tx.sender for VERIFY default code.
	if target != fc.Sender {
		return nil, gas, ErrExecutionReverted
	}

	// Charge base gas.
	if gas < defaultCodeBaseGas {
		return nil, 0, ErrOutOfGas
	}
	gas -= defaultCodeBaseGas

	var sigType byte
	var payload, legacyHeader []byte
	if current {
		sigType = input[0]
		payload = input[1:]
	} else {
		// Legacy format: embedded mode/scope byte followed by signature type.
		if len(input) < 2 {
			return nil, gas, ErrExecutionReverted
		}
		sigType = input[1]
		payload = input[2:]
		legacyHeader = input[:2]
	}

	switch sigType {
	case sigTypeSecp256k1:
		return verifySecp256k1(evm, target, payload, legacyHeader, gas, scope)
	case sigTypeP256:
		return verifyP256(evm, target, payload, legacyHeader, gas, scope)
	case sigTypeFalcon:
		return verifyFalconEOA(evm, target, payload, legacyHeader, gas, scope, false)
	case sigTypeFalconEth:
		return verifyFalconEOA(evm, target, payload, legacyHeader, gas, scope, true)
	default:
		return nil, gas, ErrExecutionReverted
	}
}

func defaultCodeSignatureHash(evm *EVM, legacyHeader []byte) []byte {
	sigHash := evm.FrameCtx.SigHash
	if len(legacyHeader) == 0 {
		return sigHash[:]
	}
	hashInput := make([]byte, len(sigHash)+len(legacyHeader))
	copy(hashInput, sigHash[:])
	copy(hashInput[len(sigHash):], legacyHeader)
	return crypto.Keccak256(hashInput)
}

// verifySecp256k1 verifies an ECDSA secp256k1 signature for EOA default code.
//
// Current payload layout: v(1) || r(32) || s(32).
// Legacy signatures hash keccak256(sig_hash || embedded_header); current
// signatures sign sig_hash directly.
func verifySecp256k1(evm *EVM, target common.Address, payload, legacyHeader []byte, gas uint64, scope uint8) ([]byte, uint64, error) {
	if len(payload) != 65 {
		return nil, gas, ErrExecutionReverted
	}

	// Charge ecrecover gas.
	if gas < params.EcrecoverGas {
		return nil, 0, ErrOutOfGas
	}
	gas -= params.EcrecoverGas

	if len(legacyHeader) != 0 {
		keccakGas := params.Keccak256Gas + 2*params.Keccak256WordGas
		if gas < keccakGas {
			return nil, 0, ErrOutOfGas
		}
		gas -= keccakGas
	}

	v := payload[0]
	r := payload[1:33]
	s := payload[33:65]
	hash := defaultCodeSignatureHash(evm, legacyHeader)

	// Build ecrecover input: (hash, v, r, s) each 32 bytes.
	// The precompile expects v as 27 or 28.
	var ecInput [128]byte
	copy(ecInput[0:32], hash)
	ecInput[63] = v + 27 // v: 0/1 → 27/28
	copy(ecInput[64:96], common.LeftPadBytes(r, 32))
	copy(ecInput[96:128], common.LeftPadBytes(s, 32))

	recovered, err := (&ecrecover{}).Run(ecInput[:])
	if err != nil || len(recovered) == 0 {
		return nil, gas, ErrExecutionReverted
	}

	// Compare recovered address with target.
	recoveredAddr := common.BytesToAddress(recovered)
	if recoveredAddr != target {
		return nil, gas, ErrExecutionReverted
	}

	// Set APPROVE.
	return applyDefaultApprove(evm, target, scope, gas)
}

// verifyP256 verifies a P256 (secp256r1) signature for EOA default code.
//
// Current payload layout: r(32) || s(32) || qx(32) || qy(32).
// Current addresses are keccak256(0x01 || qx || qy)[12:]; the legacy format
// used keccak256(qx || qy)[12:].
func verifyP256(evm *EVM, target common.Address, payload, legacyHeader []byte, gas uint64, scope uint8) ([]byte, uint64, error) {
	if len(payload) != 128 {
		return nil, gas, ErrExecutionReverted
	}

	// Charge P256 verify gas.
	if gas < params.P256VerifyGas {
		return nil, 0, ErrOutOfGas
	}
	gas -= params.P256VerifyGas

	addressWords := uint64(3)
	if len(legacyHeader) != 0 {
		addressWords = 2
	}
	keccakGas := params.Keccak256Gas + addressWords*params.Keccak256WordGas
	if len(legacyHeader) != 0 {
		keccakGas += params.Keccak256Gas + 2*params.Keccak256WordGas
	}
	if gas < keccakGas {
		return nil, 0, ErrOutOfGas
	}
	gas -= keccakGas

	r := new(big.Int).SetBytes(payload[0:32])
	s := new(big.Int).SetBytes(payload[32:64])
	qx := new(big.Int).SetBytes(payload[64:96])
	qy := new(big.Int).SetBytes(payload[96:128])

	pubKeyBytes := make([]byte, 0, 65)
	if len(legacyHeader) == 0 {
		pubKeyBytes = append(pubKeyBytes, sigTypeP256)
	}
	pubKeyBytes = append(pubKeyBytes, payload[64:128]...)
	addrHash := crypto.Keccak256(pubKeyBytes)
	derivedAddr := common.BytesToAddress(addrHash[12:])
	if derivedAddr != target {
		return nil, gas, ErrExecutionReverted
	}

	// Verify P256 signature.
	if !secp256r1.Verify(defaultCodeSignatureHash(evm, legacyHeader), r, s, qx, qy) {
		return nil, gas, ErrExecutionReverted
	}

	// Set APPROVE.
	return applyDefaultApprove(evm, target, scope, gas)
}

// verifyFalconEOA verifies a Falcon signature for EOA default code.
//
// Payload layout: pubkey(896) || sig(666).
// target must equal keccak256(ALG_TYPE || pubkey)[12:]
func verifyFalconEOA(evm *EVM, target common.Address, payload, legacyHeader []byte, gas uint64, scope uint8, useKeccak bool) ([]byte, uint64, error) {
	if len(payload) != falconPKSize+falconSigSize {
		return nil, gas, ErrExecutionReverted
	}

	// Address derivation hashes 897 bytes. Legacy signatures additionally hash
	// sig_hash || embedded_header.
	keccakGas := params.Keccak256Gas + 29*params.Keccak256WordGas
	if len(legacyHeader) != 0 {
		keccakGas += params.Keccak256Gas + 2*params.Keccak256WordGas
	}
	if gas < keccakGas {
		return nil, 0, ErrOutOfGas
	}
	gas -= keccakGas

	hashToPointAddr := common.BytesToAddress([]byte{0x14})
	if useKeccak {
		hashToPointAddr = common.BytesToAddress([]byte{0x15})
	}
	coreAddr := common.BytesToAddress([]byte{0x16})

	pubKey := payload[:falconPKSize]
	sig := payload[falconPKSize:]

	// Verify target == keccak256(ALG_TYPE || pubkey)[12:].
	derivedAddr, err := crypto.FalconPubkeyToAddress(pubKey)
	if err != nil {
		return nil, gas, ErrExecutionReverted
	}
	if useKeccak {
		addrInput := make([]byte, 1+len(pubKey))
		addrInput[0] = crypto.Falcon512EthAlgType
		copy(addrInput[1:], pubKey)
		addrHash := crypto.Keccak256(addrInput)
		derivedAddr = common.BytesToAddress(addrHash[12:])
	}
	if derivedAddr != target {
		return nil, gas, ErrExecutionReverted
	}

	hash := defaultCodeSignatureHash(evm, legacyHeader)

	// EIP-8052 HASH_TO_POINT input: msg(32B) || sig(666B)
	hashToPointInput := make([]byte, falconHashToPointInputSize)
	copy(hashToPointInput[0:falconMsgSize], hash)
	copy(hashToPointInput[falconMsgSize:], sig)

	challenge, remainingGas, err := evm.StaticCall(target, hashToPointAddr, hashToPointInput, gas)
	if err != nil {
		return nil, remainingGas, err
	}
	if len(challenge) != falconChallengeSize {
		return nil, remainingGas, ErrExecutionReverted
	}

	// EIP-8052 FALCON_CORE input: sig(666B) || pubkey(896B) || challenge(896B)
	coreInput := make([]byte, falconCoreInputSize)
	copy(coreInput[0:falconSigSize], sig)
	copy(coreInput[falconSigSize:falconSigSize+falconPKSize], pubKey)
	copy(coreInput[falconSigSize+falconPKSize:], challenge)

	ret, remainingGas, err := evm.StaticCall(target, coreAddr, coreInput, remainingGas)
	if err != nil {
		return nil, remainingGas, err
	}
	if !bytes.Equal(ret, true32Byte) {
		return nil, remainingGas, ErrExecutionReverted
	}

	// Set APPROVE.
	return applyDefaultApprove(evm, target, scope, remainingGas)
}

// applyDefaultApprove sets the APPROVE status on the EVM, mirroring what
// the APPROVE opcode does but from the default code path.
func applyDefaultApprove(evm *EVM, target common.Address, scope uint8, gas uint64) ([]byte, uint64, error) {
	status, ok := approvalStatus(uint64(scope))
	if !ok {
		return nil, gas, ErrExecutionReverted
	}

	fc := evm.FrameCtx
	if fc == nil {
		return nil, gas, ErrExecutionReverted
	}

	// Execution approval requires target to be tx.sender.
	if (status == ApproveExecution || status == ApproveBoth) && target != fc.Sender {
		return nil, gas, ErrExecutionReverted
	}

	evm.ApproveScope = status
	return nil, gas, nil
}

// executeDefaultSender implements the SENDER mode of the EOA default code.
// It decodes an RLP-encoded list of calls from frame.data[1:] and executes
// each one with msg.sender = tx.sender.
func executeDefaultSender(evm *EVM, target common.Address, input []byte, gas uint64, scope uint8) ([]byte, uint64, error) {
	fc := evm.FrameCtx
	if fc == nil {
		return nil, gas, ErrExecutionReverted
	}

	// High nibble (scope) must be 0 for SENDER mode.
	if scope != 0 {
		return nil, gas, ErrExecutionReverted
	}

	// frame.target must equal tx.sender.
	if target != fc.Sender {
		return nil, gas, ErrExecutionReverted
	}

	// Charge base gas.
	if gas < defaultCodeBaseGas {
		return nil, 0, ErrOutOfGas
	}
	gas -= defaultCodeBaseGas

	// Decode RLP calls from input[1:].
	if len(input) < 2 {
		return nil, gas, ErrExecutionReverted
	}

	var calls []eoaCallRLP
	if err := rlp.DecodeBytes(input[1:], &calls); err != nil {
		return nil, gas, ErrExecutionReverted
	}

	// Execute each call.
	for _, call := range calls {
		value, _ := uint256.FromBig(call.Value)
		if value == nil {
			value = new(uint256.Int)
		}

		ret, leftOver, err := evm.Call(fc.Sender, call.Target, call.Data, gas, value)
		gas = leftOver
		_ = ret

		if err != nil {
			// Any call revert causes the whole frame to revert.
			return nil, gas, ErrExecutionReverted
		}
	}

	return nil, gas, nil
}

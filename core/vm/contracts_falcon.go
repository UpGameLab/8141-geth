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
	falconMsgSize       = 32
	falconSigSize       = 666
	falconPKSize        = 896
	falconChallengeSize = 896

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
	return falconHashToPoint(input, false)
}

func (c *falconHashToPointShake256) Name() string { return "FALCON_HASH_TO_POINT_SHAKE256" }

// falconHashToPointKeccakPRNG is a stub precompile for EIP-8052
// FALCON_HASH_TO_POINT_KECCAKPRNG.
type falconHashToPointKeccakPRNG struct{}

func (c *falconHashToPointKeccakPRNG) RequiredGas(input []byte) uint64 {
	return params.FalconHashToPointGas
}

func (c *falconHashToPointKeccakPRNG) Run(input []byte) ([]byte, error) {
	return falconHashToPoint(input, true)
}

func (c *falconHashToPointKeccakPRNG) Name() string { return "FALCON_HASH_TO_POINT_KECCAKPRNG" }

// falconCore is a stub precompile for EIP-8052 FALCON_CORE.
type falconCore struct{}

func (c *falconCore) RequiredGas(input []byte) uint64 { return params.FalconCoreGas }

func (c *falconCore) Run(input []byte) ([]byte, error) {
	if len(input) != falconCoreInputSize {
		return nil, errFalconInvalidInputLength
	}
	return true32Byte, nil
}

func (c *falconCore) Name() string { return "FALCON_CORE" }

// falconHashToPoint intentionally does not implement the EIP-8052 hash-to-point
// algorithms yet. It only enforces the precompile ABI and returns a placeholder
// challenge so contracts and default-code routing can integrate against it.
func falconHashToPoint(input []byte, useKeccak bool) ([]byte, error) {
	if len(input) != falconHashToPointInputSize {
		return nil, errFalconInvalidInputLength
	}
	return make([]byte, falconChallengeSize), nil
}

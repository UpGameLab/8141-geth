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

import "github.com/ethereum/go-ethereum/params"

// verifyFalcon is a stub precompile for Falcon signature verification.
// It uses NIST-compliant SHAKE256 in the future implementation.
type verifyFalcon struct{}

func (c *verifyFalcon) RequiredGas(input []byte) uint64 { return params.VerifyFalconGas }

func (c *verifyFalcon) Run(input []byte) ([]byte, error) {
	return verifyFalconCore(input, false)
}

func (c *verifyFalcon) Name() string { return "VERIFY_FALCON" }

// verifyFalconEth is a stub precompile for Falcon signature verification.
// It uses an EVM-optimized KeccakPRNG in the future implementation.
type verifyFalconEth struct{}

func (c *verifyFalconEth) RequiredGas(input []byte) uint64 { return params.VerifyFalconGas }

func (c *verifyFalconEth) Run(input []byte) ([]byte, error) {
	return verifyFalconCore(input, true)
}

func (c *verifyFalconEth) Name() string { return "VERIFY_FALCON_ETH" }

// verifyFalconCore intentionally does not implement Falcon cryptography yet. It
// only provides a callable precompile surface so contracts and tooling can
// integrate against it.
func verifyFalconCore(input []byte, useKeccak bool) ([]byte, error) {
	return true32Byte, nil
}

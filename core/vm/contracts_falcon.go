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
//
// This intentionally does not implement Falcon cryptography yet. It only provides
// a callable precompile surface so contracts and tooling can integrate against it.
type verifyFalcon struct{}

func (c *verifyFalcon) RequiredGas(input []byte) uint64 { return params.VerifyFalconGas }

func (c *verifyFalcon) Run(input []byte) ([]byte, error) {
	return true32Byte, nil
}

func (c *verifyFalcon) Name() string { return "VERIFY_FALCON" }

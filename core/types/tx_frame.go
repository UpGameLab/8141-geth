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

package types

import (
	"bytes"
	"io"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

// Frame mode constants as defined in EIP-8141.
const (
	FrameModeDefault uint8 = 0 // Execute as ENTRY_POINT caller.
	FrameModeVerify  uint8 = 1 // Validation frame (static, must APPROVE).
	FrameModeSender  uint8 = 2 // Execute as tx.sender caller.
)

// Frame represents a single execution frame in a frame transaction (EIP-8141).
//
// RLP encoding: [mode, target, gas_limit, data]
// When target is nil, it resolves to tx.sender at execution time.
type Frame struct {
	Mode     uint8
	Target   *common.Address // nil means tx.sender
	GasLimit uint64
	Data     []byte
}

// EncodeRLP implements rlp.Encoder for Frame.
// Nil target is encoded as empty bytes.
func (f *Frame) EncodeRLP(w io.Writer) error {
	var target []byte
	if f.Target != nil {
		target = f.Target.Bytes()
	}
	return rlp.Encode(w, []any{f.Mode, target, f.GasLimit, f.Data})
}

// DecodeRLP implements rlp.Decoder for Frame.
func (f *Frame) DecodeRLP(s *rlp.Stream) error {
	var dec struct {
		Mode     uint8
		Target   []byte
		GasLimit uint64
		Data     []byte
	}
	if err := s.Decode(&dec); err != nil {
		return err
	}
	f.Mode = dec.Mode
	f.GasLimit = dec.GasLimit
	f.Data = dec.Data
	if len(dec.Target) > 0 {
		addr := common.BytesToAddress(dec.Target)
		f.Target = &addr
	}
	return nil
}

// FrameTx implements the EIP-8141 frame transaction.
//
// RLP encoding:
// [chain_id, nonce, sender, frames, max_priority_fee_per_gas, max_fee_per_gas,
//
//	max_fee_per_blob_gas, blob_versioned_hashes]
type FrameTx struct {
	ChainID    *uint256.Int
	Nonce      uint64
	Sender     common.Address
	Frames     []Frame
	GasTipCap  *uint256.Int  // max_priority_fee_per_gas
	GasFeeCap  *uint256.Int  // max_fee_per_gas
	BlobFeeCap *uint256.Int  // max_fee_per_blob_gas
	BlobHashes []common.Hash // blob_versioned_hashes
}

// TotalGas returns the total gas limit of the frame transaction as defined in
// EIP-8141: FRAME_TX_INTRINSIC_COST + calldata_cost(rlp(frames)) + sum(frame.gas_limit).
// The calldata cost is not included here as it requires the encoded frame data;
// this method returns the sum of frame gas limits plus intrinsic cost.
func (tx *FrameTx) TotalGas() uint64 {
	total := uint64(params.TxGasEIP8141)
	for _, f := range tx.Frames {
		total += f.GasLimit
	}
	return total
}

// copy creates a deep copy of the transaction data and initializes all fields.
func (tx *FrameTx) copy() TxData {
	cpy := &FrameTx{
		Nonce:      tx.Nonce,
		Sender:     tx.Sender,
		Frames:     make([]Frame, len(tx.Frames)),
		BlobHashes: make([]common.Hash, len(tx.BlobHashes)),
		ChainID:    new(uint256.Int),
		GasTipCap:  new(uint256.Int),
		GasFeeCap:  new(uint256.Int),
		BlobFeeCap: new(uint256.Int),
	}
	// Deep copy frames.
	for i, f := range tx.Frames {
		cpy.Frames[i] = Frame{
			Mode:     f.Mode,
			GasLimit: f.GasLimit,
			Data:     common.CopyBytes(f.Data),
		}
		if f.Target != nil {
			target := *f.Target
			cpy.Frames[i].Target = &target
		}
	}
	copy(cpy.BlobHashes, tx.BlobHashes)
	if tx.ChainID != nil {
		cpy.ChainID.Set(tx.ChainID)
	}
	if tx.GasTipCap != nil {
		cpy.GasTipCap.Set(tx.GasTipCap)
	}
	if tx.GasFeeCap != nil {
		cpy.GasFeeCap.Set(tx.GasFeeCap)
	}
	if tx.BlobFeeCap != nil {
		cpy.BlobFeeCap.Set(tx.BlobFeeCap)
	}
	return cpy
}

// accessors for innerTx.
func (tx *FrameTx) txType() byte           { return FrameTxType }
func (tx *FrameTx) chainID() *big.Int      { return tx.ChainID.ToBig() }
func (tx *FrameTx) accessList() AccessList  { return nil }
func (tx *FrameTx) data() []byte           { return nil }
func (tx *FrameTx) gas() uint64            { return tx.TotalGas() }
func (tx *FrameTx) gasFeeCap() *big.Int    { return tx.GasFeeCap.ToBig() }
func (tx *FrameTx) gasTipCap() *big.Int    { return tx.GasTipCap.ToBig() }
func (tx *FrameTx) gasPrice() *big.Int     { return tx.GasFeeCap.ToBig() }
func (tx *FrameTx) value() *big.Int        { return new(big.Int) }
func (tx *FrameTx) nonce() uint64          { return tx.Nonce }
func (tx *FrameTx) to() *common.Address    { return nil }
func (tx *FrameTx) blobGas() uint64        { return params.BlobTxBlobGasPerBlob * uint64(len(tx.BlobHashes)) }
func (tx *FrameTx) BlobGas() uint64        { return tx.blobGas() }

func (tx *FrameTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	if baseFee == nil {
		return dst.Set(tx.GasFeeCap.ToBig())
	}
	tip := dst.Sub(tx.GasFeeCap.ToBig(), baseFee)
	if tip.Cmp(tx.GasTipCap.ToBig()) > 0 {
		tip.Set(tx.GasTipCap.ToBig())
	}
	return tip.Add(tip, baseFee)
}

// rawSignatureValues returns zero values since frame transactions do not use
// ECDSA signatures. Authentication is performed via VERIFY frames.
func (tx *FrameTx) rawSignatureValues() (v, r, s *big.Int) {
	return new(big.Int), new(big.Int), new(big.Int)
}

// setSignatureValues is a no-op for frame transactions.
func (tx *FrameTx) setSignatureValues(chainID, v, r, s *big.Int) {}

func (tx *FrameTx) encode(b *bytes.Buffer) error {
	return rlp.Encode(b, tx)
}

func (tx *FrameTx) decode(input []byte) error {
	return rlp.DecodeBytes(input, tx)
}

// rlpFramesData returns the RLP-encoded frames as a byte slice.
func (tx *FrameTx) rlpFramesData() []byte {
	var buf bytes.Buffer
	rlp.Encode(&buf, tx.Frames)
	return buf.Bytes()
}

// CalldataGas returns the calldata cost of the RLP-encoded frames.
// Per EIP-8141: calldata_cost(rlp(tx.frames)) using EIP-2028 gas costs.
func (tx *FrameTx) CalldataGas() uint64 {
	data := tx.rlpFramesData()
	z := uint64(bytes.Count(data, []byte{0}))
	nz := uint64(len(data)) - z
	return z*params.TxDataZeroGas + nz*params.TxDataNonZeroGasEIP2028
}

// FloorDataGas returns the EIP-7623 floor data gas for a frame transaction.
// floor = TxGasEIP8141 + tokens * TxCostFloorPerToken
func (tx *FrameTx) FloorDataGas() uint64 {
	data := tx.rlpFramesData()
	z := uint64(bytes.Count(data, []byte{0}))
	nz := uint64(len(data)) - z
	tokens := nz*params.TxTokenPerNonZeroByte + z
	return params.TxGasEIP8141 + tokens*params.TxCostFloorPerToken
}

// SigHash returns the exported signature hash for the frame transaction.
func (tx *FrameTx) SigHash(chainID *big.Int) common.Hash {
	return tx.sigHash(chainID)
}

// sigHash returns the signature hash for the frame transaction.
// Per EIP-8141, VERIFY frames have their data elided from the hash.
func (tx *FrameTx) sigHash(chainID *big.Int) common.Hash {
	// Build frames with VERIFY data elided.
	type frameSigHash struct {
		Mode     uint8
		Target   *common.Address
		GasLimit uint64
		Data     []byte
	}
	frames := make([]frameSigHash, len(tx.Frames))
	for i, f := range tx.Frames {
		frames[i] = frameSigHash{
			Mode:     f.Mode,
			Target:   f.Target,
			GasLimit: f.GasLimit,
		}
		if f.Mode != FrameModeVerify {
			frames[i].Data = f.Data
		}
		// VERIFY frames get nil Data (elided).
	}
	return prefixedRlpHash(
		FrameTxType,
		[]any{
			chainID,
			tx.Nonce,
			tx.Sender,
			frames,
			tx.GasTipCap,
			tx.GasFeeCap,
			tx.BlobFeeCap,
			tx.BlobHashes,
		})
}

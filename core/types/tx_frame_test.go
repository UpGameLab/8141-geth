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
	"math"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/holiman/uint256"
)

// testFrameTx returns a FrameTx with some default test values.
func testFrameTx() *FrameTx {
	target := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	return &FrameTx{
		ChainID:    uint256.NewInt(1),
		Nonce:      42,
		Sender:     common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		GasTipCap:  uint256.NewInt(1_000_000_000),  // 1 gwei
		GasFeeCap:  uint256.NewInt(30_000_000_000), // 30 gwei
		BlobFeeCap: uint256.NewInt(0),
		BlobHashes: []common.Hash{},
		Frames: []Frame{
			{Mode: FrameModeVerify, Target: nil, GasLimit: 100_000, Data: []byte("signature")},
			{Mode: FrameModeSender, Target: &target, GasLimit: 200_000, Data: []byte("calldata")},
		},
	}
}

func TestFrameTxType(t *testing.T) {
	ftx := testFrameTx()
	if ftx.txType() != FrameTxType {
		t.Errorf("txType() = %d, want %d", ftx.txType(), FrameTxType)
	}
	if FrameTxType != 0x06 {
		t.Errorf("FrameTxType = %d, want 0x06", FrameTxType)
	}
}

func TestFrameTxTotalGas(t *testing.T) {
	ftx := testFrameTx()
	want := uint64(params.TxGasEIP8141) + 100_000 + 200_000
	if got := ftx.TotalGas(); got != want {
		t.Errorf("TotalGas() = %d, want %d", got, want)
	}
}

func TestFrameTxAccessors(t *testing.T) {
	ftx := testFrameTx()
	if ftx.chainID().Uint64() != 1 {
		t.Errorf("chainID() = %d, want 1", ftx.chainID().Uint64())
	}
	if ftx.nonce() != 42 {
		t.Errorf("nonce() = %d, want 42", ftx.nonce())
	}
	if ftx.accessList() != nil {
		t.Error("accessList() should be nil")
	}
	if ftx.data() != nil {
		t.Error("data() should be nil")
	}
	if ftx.to() != nil {
		t.Error("to() should be nil")
	}
	if ftx.value().Sign() != 0 {
		t.Error("value() should be zero")
	}
	if ftx.gas() != ftx.TotalGas() {
		t.Errorf("gas() = %d, want %d", ftx.gas(), ftx.TotalGas())
	}
	if ftx.gasFeeCap().Uint64() != 30_000_000_000 {
		t.Errorf("gasFeeCap() = %d, want 30000000000", ftx.gasFeeCap().Uint64())
	}
	if ftx.gasTipCap().Uint64() != 1_000_000_000 {
		t.Errorf("gasTipCap() = %d, want 1000000000", ftx.gasTipCap().Uint64())
	}
}

func TestFrameTxSignatureIsZero(t *testing.T) {
	ftx := testFrameTx()
	v, r, s := ftx.rawSignatureValues()
	if v.Sign() != 0 || r.Sign() != 0 || s.Sign() != 0 {
		t.Error("rawSignatureValues() should return zero values for frame tx")
	}
}

func TestFrameTxCopy(t *testing.T) {
	ftx := testFrameTx()
	cpy := ftx.copy().(*FrameTx)

	// Verify deep copy independence.
	cpy.Nonce = 99
	if ftx.Nonce == cpy.Nonce {
		t.Error("copy() did not deep copy Nonce")
	}

	cpy.Frames[0].Data[0] = 0xff
	if ftx.Frames[0].Data[0] == 0xff {
		t.Error("copy() did not deep copy frame Data")
	}

	cpy.ChainID.SetUint64(999)
	if ftx.ChainID.Uint64() == 999 {
		t.Error("copy() did not deep copy ChainID")
	}
}

func TestFrameTxSigHashElidesVerifyData(t *testing.T) {
	ftx := testFrameTx()
	hash1 := ftx.sigHash(ftx.chainID())

	// Change the VERIFY frame's data - hash should NOT change.
	ftx2 := testFrameTx()
	ftx2.Frames[0].Data = []byte("different_signature")
	hash2 := ftx2.sigHash(ftx2.chainID())

	if hash1 != hash2 {
		t.Error("sigHash should be identical when only VERIFY frame data differs")
	}

	// Change the SENDER frame's data - hash SHOULD change.
	ftx3 := testFrameTx()
	ftx3.Frames[1].Data = []byte("different_calldata")
	hash3 := ftx3.sigHash(ftx3.chainID())

	if hash1 == hash3 {
		t.Error("sigHash should differ when non-VERIFY frame data changes")
	}
}

func TestFrameTxRLPRoundTrip(t *testing.T) {
	ftx := testFrameTx()
	tx := NewTx(ftx)

	// Encode.
	var buf bytes.Buffer
	if err := tx.EncodeRLP(&buf); err != nil {
		t.Fatalf("EncodeRLP failed: %v", err)
	}

	// Decode.
	var decoded Transaction
	if err := rlp.DecodeBytes(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("DecodeRLP failed: %v", err)
	}

	// Verify type.
	if decoded.Type() != FrameTxType {
		t.Errorf("decoded type = %d, want %d", decoded.Type(), FrameTxType)
	}
	// Verify nonce.
	if decoded.Nonce() != 42 {
		t.Errorf("decoded nonce = %d, want 42", decoded.Nonce())
	}
	// Verify sender.
	if decoded.FrameSender() != ftx.Sender {
		t.Errorf("decoded sender = %s, want %s", decoded.FrameSender(), ftx.Sender)
	}
	// Verify frames.
	frames := decoded.Frames()
	if len(frames) != 2 {
		t.Fatalf("decoded frames = %d, want 2", len(frames))
	}
	if frames[0].Mode != FrameModeVerify {
		t.Errorf("frame[0].Mode = %d, want %d", frames[0].Mode, FrameModeVerify)
	}
	if frames[1].Mode != FrameModeSender {
		t.Errorf("frame[1].Mode = %d, want %d", frames[1].Mode, FrameModeSender)
	}
	if !bytes.Equal(frames[1].Data, []byte("calldata")) {
		t.Errorf("frame[1].Data = %x, want 'calldata'", frames[1].Data)
	}
}

func TestFrameTxMarshalBinaryRoundTrip(t *testing.T) {
	ftx := testFrameTx()
	tx := NewTx(ftx)

	// MarshalBinary.
	enc, err := tx.MarshalBinary()
	if err != nil {
		t.Fatalf("MarshalBinary failed: %v", err)
	}

	// First byte should be FrameTxType.
	if enc[0] != FrameTxType {
		t.Errorf("first byte = 0x%02x, want 0x%02x", enc[0], FrameTxType)
	}

	// UnmarshalBinary.
	var decoded Transaction
	if err := decoded.UnmarshalBinary(enc); err != nil {
		t.Fatalf("UnmarshalBinary failed: %v", err)
	}

	if decoded.Type() != FrameTxType {
		t.Errorf("decoded type = %d, want %d", decoded.Type(), FrameTxType)
	}
	if decoded.Nonce() != 42 {
		t.Errorf("decoded nonce = %d, want 42", decoded.Nonce())
	}
}

func TestFrameTxBlobFields(t *testing.T) {
	ftx := testFrameTx()
	ftx.BlobFeeCap = uint256.NewInt(100)
	ftx.BlobHashes = []common.Hash{
		common.HexToHash("0x01"),
		common.HexToHash("0x02"),
	}

	tx := NewTx(ftx)

	if tx.BlobGasFeeCap().Uint64() != 100 {
		t.Errorf("BlobGasFeeCap = %d, want 100", tx.BlobGasFeeCap().Uint64())
	}
	if len(tx.BlobHashes()) != 2 {
		t.Errorf("BlobHashes len = %d, want 2", len(tx.BlobHashes()))
	}
	wantBlobGas := uint64(2 * params.BlobTxBlobGasPerBlob)
	if tx.BlobGas() != wantBlobGas {
		t.Errorf("BlobGas = %d, want %d", tx.BlobGas(), wantBlobGas)
	}
}

func TestFrameTxNilTarget(t *testing.T) {
	ftx := testFrameTx()
	// First frame has nil target (meaning tx.sender).
	if ftx.Frames[0].Target != nil {
		t.Error("frame[0].Target should be nil")
	}

	// Verify deep copy preserves nil target.
	cpy := ftx.copy().(*FrameTx)
	if cpy.Frames[0].Target != nil {
		t.Error("copy frame[0].Target should still be nil")
	}
}

func TestFrameTxTransactionAccessors(t *testing.T) {
	ftx := testFrameTx()
	tx := NewTx(ftx)

	// Frame-specific accessors.
	if tx.FrameSender() != ftx.Sender {
		t.Errorf("FrameSender() = %s, want %s", tx.FrameSender(), ftx.Sender)
	}
	if len(tx.Frames()) != 2 {
		t.Errorf("Frames() len = %d, want 2", len(tx.Frames()))
	}

	// Generic accessors.
	if tx.To() != nil {
		t.Error("To() should be nil for frame tx")
	}
	if tx.Value().Sign() != 0 {
		t.Error("Value() should be zero for frame tx")
	}
	if tx.Gas() != ftx.TotalGas() {
		t.Errorf("Gas() = %d, want %d", tx.Gas(), ftx.TotalGas())
	}

	// Non-frame tx should return zero FrameSender.
	legacyTx := NewTx(&LegacyTx{Nonce: 1})
	if (legacyTx.FrameSender() != common.Address{}) {
		t.Error("FrameSender() on legacy tx should be zero address")
	}
	if legacyTx.Frames() != nil {
		t.Error("Frames() on legacy tx should be nil")
	}
}

func TestFrameTxSigner(t *testing.T) {
	ftx := testFrameTx()
	tx := NewTx(ftx)
	signer := NewPragueSigner(ftx.chainID())

	// Sender should return the explicit sender from the tx.
	sender, err := Sender(signer, tx)
	if err != nil {
		t.Fatalf("Sender failed: %v", err)
	}
	if sender != ftx.Sender {
		t.Errorf("Sender = %s, want %s", sender, ftx.Sender)
	}

	// Hash should work.
	hash := signer.Hash(tx)
	if hash == (common.Hash{}) {
		t.Error("Hash should not be zero")
	}

	// SignatureValues should return zero values.
	r, s, v, err := signer.SignatureValues(tx, nil)
	if err != nil {
		t.Fatalf("SignatureValues failed: %v", err)
	}
	if r.Sign() != 0 || s.Sign() != 0 || v.Sign() != 0 {
		t.Error("SignatureValues should return zeros for frame tx")
	}
}

func TestFrameDecodeRLPRejectsInvalidTargetLength(t *testing.T) {
	tests := []int{1, common.AddressLength - 1, common.AddressLength + 1, 32}
	for _, n := range tests {
		payload, err := rlp.EncodeToBytes([]any{
			uint8(FrameModeDefault),
			bytes.Repeat([]byte{0x11}, n),
			uint64(1),
			[]byte{0x01},
		})
		if err != nil {
			t.Fatalf("failed to encode frame with target len %d: %v", n, err)
		}
		var frame Frame
		err = rlp.DecodeBytes(payload, &frame)
		if err == nil {
			t.Fatalf("expected decode error for target len %d, got nil", n)
		}
		if !strings.Contains(err.Error(), "invalid frame target length") {
			t.Fatalf("unexpected error for target len %d: %v", n, err)
		}
	}
}

func TestFrameDecodeRLPResetsNilTarget(t *testing.T) {
	target := common.HexToAddress("0x1234567890abcdef1234567890abcdef12345678")
	frame := Frame{Target: &target}

	payload, err := rlp.EncodeToBytes([]any{
		uint8(FrameModeVerify),
		[]byte{},
		uint64(100),
		[]byte("sig"),
	})
	if err != nil {
		t.Fatalf("failed to encode frame payload: %v", err)
	}
	if err := rlp.DecodeBytes(payload, &frame); err != nil {
		t.Fatalf("failed to decode frame payload: %v", err)
	}
	if frame.Target != nil {
		t.Fatalf("expected nil target, got %v", *frame.Target)
	}
}

// TestFrameTxTotalGasOverflow verifies that TotalGas() clamps to math.MaxUint64
// rather than wrapping around when the sum of frame gas limits overflows uint64.
func TestFrameTxTotalGasOverflow(t *testing.T) {
	// Frame 1: MaxUint64 - 100, Frame 2: 200 → sum overflows uint64.
	ftx := &FrameTx{
		ChainID:    uint256.NewInt(1),
		Sender:     common.Address{},
		GasTipCap:  uint256.NewInt(0),
		GasFeeCap:  uint256.NewInt(0),
		BlobFeeCap: uint256.NewInt(0),
		Frames: []Frame{
			{Mode: FrameModeDefault, GasLimit: math.MaxUint64 - 100},
			{Mode: FrameModeDefault, GasLimit: 200},
		},
	}
	if got := ftx.TotalGas(); got != math.MaxUint64 {
		t.Errorf("TotalGas() with overflow = %d, want math.MaxUint64 (%d)", got, uint64(math.MaxUint64))
	}
}

// TestFrameTxCalldataGas verifies CalldataGas() returns (uint64, nil) on normal input
// and that the gas value is proportional to the frame data size.
func TestFrameTxCalldataGas(t *testing.T) {
	// Normal tx with frame data: should return a positive gas value with no error.
	ftx := testFrameTx()
	gas, err := ftx.CalldataGas()
	if err != nil {
		t.Fatalf("CalldataGas() unexpected error: %v", err)
	}
	if gas == 0 {
		t.Error("CalldataGas() returned 0 for a tx with non-empty frame data")
	}

	// Empty frames list: should still return (value, nil).
	ftxEmpty := &FrameTx{
		ChainID:    uint256.NewInt(1),
		Sender:     common.Address{},
		GasTipCap:  uint256.NewInt(0),
		GasFeeCap:  uint256.NewInt(0),
		BlobFeeCap: uint256.NewInt(0),
	}
	gasEmpty, err := ftxEmpty.CalldataGas()
	if err != nil {
		t.Fatalf("CalldataGas() for empty frames unexpected error: %v", err)
	}
	// Empty frame list RLP is minimal; gas from non-empty frames should be higher.
	if gasEmpty >= gas {
		t.Errorf("empty frames CalldataGas %d should be < non-empty frames CalldataGas %d", gasEmpty, gas)
	}
}

// TestFrameTxFloorDataGas verifies FloorDataGas() returns (uint64, nil) on normal input
// and that the result is at least TxGasEIP8141.
func TestFrameTxFloorDataGas(t *testing.T) {
	ftx := testFrameTx()
	floor, err := ftx.FloorDataGas()
	if err != nil {
		t.Fatalf("FloorDataGas() unexpected error: %v", err)
	}
	if floor < uint64(params.TxGasEIP8141) {
		t.Errorf("FloorDataGas() = %d, want >= TxGasEIP8141 (%d)", floor, params.TxGasEIP8141)
	}

	// Empty frames: floor = TxGasEIP8141 + cost of minimal RLP list.
	ftxEmpty := &FrameTx{
		ChainID:    uint256.NewInt(1),
		Sender:     common.Address{},
		GasTipCap:  uint256.NewInt(0),
		GasFeeCap:  uint256.NewInt(0),
		BlobFeeCap: uint256.NewInt(0),
	}
	floorEmpty, err := ftxEmpty.FloorDataGas()
	if err != nil {
		t.Fatalf("FloorDataGas() for empty frames unexpected error: %v", err)
	}
	if floorEmpty < uint64(params.TxGasEIP8141) {
		t.Errorf("FloorDataGas() empty = %d, want >= TxGasEIP8141 (%d)", floorEmpty, params.TxGasEIP8141)
	}
}

func TestFrameTxUnmarshalBinaryRejectsInvalidTargetLength(t *testing.T) {
	type rawFrame struct {
		Mode     uint8
		Target   []byte
		GasLimit uint64
		Data     []byte
	}
	type rawFrameTx struct {
		ChainID    *uint256.Int
		Nonce      uint64
		Sender     common.Address
		Frames     []rawFrame
		GasTipCap  *uint256.Int
		GasFeeCap  *uint256.Int
		BlobFeeCap *uint256.Int
		BlobHashes []common.Hash
	}

	raw := rawFrameTx{
		ChainID: uint256.NewInt(1),
		Nonce:   1,
		Sender:  common.HexToAddress("0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
		Frames: []rawFrame{
			{
				Mode:     FrameModeVerify,
				Target:   bytes.Repeat([]byte{0x01}, common.AddressLength-1),
				GasLimit: 100000,
				Data:     []byte("signature"),
			},
		},
		GasTipCap:  uint256.NewInt(1),
		GasFeeCap:  uint256.NewInt(1),
		BlobFeeCap: uint256.NewInt(0),
		BlobHashes: nil,
	}
	payload, err := rlp.EncodeToBytes(raw)
	if err != nil {
		t.Fatalf("failed to encode malformed frame tx: %v", err)
	}
	rawTx := append([]byte{FrameTxType}, payload...)

	var tx Transaction
	err = tx.UnmarshalBinary(rawTx)
	if err == nil {
		t.Fatal("expected UnmarshalBinary to fail for invalid frame target length")
	}
	if !strings.Contains(err.Error(), "invalid frame target length") {
		t.Fatalf("unexpected error: %v", err)
	}
}

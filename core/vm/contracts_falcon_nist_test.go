// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package vm

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

type falconNISTVector struct {
	count int
	msg   []byte
	pk    []byte
	sig   []byte
}

func loadFalconNISTVectors(t *testing.T) []falconNISTVector {
	t.Helper()

	f, err := os.Open("testdata/PQCsignKAT_1281.rsp")
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("testdata/PQCsignKAT_1281.rsp is absent")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var vectors []falconNISTVector
	cur := map[string]string{}
	flush := func() {
		if len(cur) == 0 {
			return
		}
		count, err := strconv.Atoi(cur["count"])
		if err != nil {
			t.Fatalf("invalid count %q: %v", cur["count"], err)
		}
		mlen, err := strconv.Atoi(cur["mlen"])
		if err != nil {
			t.Fatalf("vector %d: invalid mlen %q: %v", count, cur["mlen"], err)
		}
		msg := mustDecodeNISTHex(t, cur["msg"])
		pk := mustDecodeNISTHex(t, cur["pk"])
		sm := mustDecodeNISTHex(t, cur["sm"])

		if len(msg) != mlen {
			t.Fatalf("vector %d: msg size %d, want %d", count, len(msg), mlen)
		}
		if len(pk) != falconPKSize+1 || pk[0] != 0x09 {
			t.Fatalf("vector %d: unexpected encoded public key size/header: len=%d header=%#x", count, len(pk), pk[0])
		}
		if len(sm) < 2+falconNonceSize {
			t.Fatalf("vector %d: signed message too short: %d", count, len(sm))
		}

		sigLen := int(sm[0])<<8 | int(sm[1])
		msgLen := len(sm) - 2 - falconNonceSize - sigLen
		if msgLen < 0 {
			t.Fatalf("vector %d: signature length %d exceeds sm size %d", count, sigLen, len(sm))
		}
		if msgLen != mlen {
			t.Fatalf("vector %d: sm message length %d, want %d", count, msgLen, mlen)
		}
		msgFromSM := sm[2+falconNonceSize : 2+falconNonceSize+msgLen]
		if !bytes.Equal(msgFromSM, msg) {
			t.Fatalf("vector %d: embedded signed message does not match msg field", count)
		}

		compactSig := sm[2+falconNonceSize+msgLen:]
		if len(compactSig) != sigLen {
			t.Fatalf("vector %d: compact signature size %d, want %d", count, len(compactSig), sigLen)
		}
		if sigLen < 1 || compactSig[0] != 0x29 {
			t.Fatalf("vector %d: unexpected compact signature header %#x", count, compactSig[0])
		}
		if sigLen-1 > falconSigBodySize {
			t.Fatalf("vector %d: compact signature body size %d exceeds padded size %d", count, sigLen-1, falconSigBodySize)
		}

		sig := make([]byte, falconSigSize)
		sig[0] = falconSigHeader
		copy(sig[falconSigHdrSize:falconSigHdrSize+falconNonceSize], sm[2:2+falconNonceSize])
		copy(sig[falconSigHdrSize+falconNonceSize:], compactSig[1:])

		vectors = append(vectors, falconNISTVector{
			count: count,
			msg:   msg,
			pk:    pk[1:],
			sig:   sig,
		})
		cur = map[string]string{}
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(nil, 2*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "count" {
			flush()
		}
		cur[key] = value
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
	flush()
	if len(vectors) != 100 {
		t.Fatalf("loaded %d vectors, want 100", len(vectors))
	}
	return vectors
}

func mustDecodeNISTHex(t *testing.T, s string) []byte {
	t.Helper()
	out, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid hex: %v", err)
	}
	return out
}

func verifyFalconNISTVector(t *testing.T, msg, pk, sig []byte) bool {
	t.Helper()

	hashToPoint, ok := PrecompiledContractsFalcon[common.BytesToAddress([]byte{0x14})]
	if !ok {
		t.Fatal("missing 0x14 Falcon hash-to-point precompile")
	}
	core, ok := PrecompiledContractsFalcon[common.BytesToAddress([]byte{0x16})]
	if !ok {
		t.Fatal("missing 0x16 Falcon core precompile")
	}

	hashInput := make([]byte, len(msg)+falconSigSize)
	copy(hashInput, msg)
	copy(hashInput[len(msg):], sig)
	challenge, err := hashToPoint.Run(hashInput)
	if err != nil {
		t.Fatal(err)
	}

	coreInput := make([]byte, falconCoreInputSize)
	copy(coreInput[:falconChallengeSize], challenge)
	copy(coreInput[falconChallengeSize:falconChallengeSize+falconSigSize], sig)
	copy(coreInput[falconChallengeSize+falconSigSize:], pk)
	ret, err := core.Run(coreInput)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Equal(ret, true32Byte)
}

func TestFalconNISTKAT(t *testing.T) {
	vectors := loadFalconNISTVectors(t)
	for _, v := range vectors {
		if !verifyFalconNISTVector(t, v.msg, v.pk, v.sig) {
			t.Fatalf("vector %d: verification failed", v.count)
		}
	}
	t.Logf("%d NIST Falcon-512 vectors returned true", len(vectors))
}

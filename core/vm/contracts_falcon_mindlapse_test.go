// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.

package vm

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"testing"
)

type falconMindlapseVector struct {
	count int
	msg   []byte
	pk    []byte
	sig   []byte
}

func loadFalconMindlapseVectors(t *testing.T) []falconMindlapseVector {
	t.Helper()

	f, err := os.Open("testdata/falcon512-mindlapse-KAT.rsp")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var vectors []falconMindlapseVector
	cur := map[string]string{}
	flush := func() {
		if len(cur) == 0 {
			return
		}
		count, err := strconv.Atoi(cur["count"])
		if err != nil {
			t.Fatalf("invalid count %q: %v", cur["count"], err)
		}
		msg := mustDecodeMindlapseHex(t, cur["msg"])
		pk := mustDecodeMindlapseHex(t, cur["pk"])
		sm := mustDecodeMindlapseHex(t, cur["sm"])

		if len(msg) != falconMsgSize {
			t.Fatalf("vector %d: msg size %d, want %d", count, len(msg), falconMsgSize)
		}
		if len(pk) != falconPKSize+1 || pk[0] != 0x09 {
			t.Fatalf("vector %d: unexpected encoded public key size/header: len=%d header=%#x", count, len(pk), pk[0])
		}
		if len(sm) < 2+falconNonceSize+falconMsgSize {
			t.Fatalf("vector %d: signed message too short: %d", count, len(sm))
		}
		bodyLen := int(sm[0])<<8 | int(sm[1])
		if bodyLen < 1 {
			t.Fatalf("vector %d: signature body length %d is too short", count, bodyLen)
		}
		if sm[2+falconNonceSize+falconMsgSize] != 0x29 {
			t.Fatalf("vector %d: unexpected compact signature header %#x", count, sm[2+falconNonceSize+falconMsgSize])
		}
		if bodyLen-1 > falconSigBodySize {
			t.Fatalf("vector %d: signature body length %d exceeds padded size %d", count, bodyLen, falconSigBodySize)
		}
		if len(sm) != 2+falconNonceSize+falconMsgSize+bodyLen {
			t.Fatalf("vector %d: sm size %d does not match encoded body length %d", count, len(sm), bodyLen)
		}
		if !bytes.Equal(sm[2+falconNonceSize:2+falconNonceSize+falconMsgSize], msg) {
			t.Fatalf("vector %d: embedded signed message does not match msg field", count)
		}

		sig := make([]byte, falconSigSize)
		sig[0] = falconSigHeader
		copy(sig[falconSigHdrSize:falconSigHdrSize+falconNonceSize], sm[2:2+falconNonceSize])
		copy(sig[falconSigHdrSize+falconNonceSize:], sm[2+falconNonceSize+falconMsgSize+1:])

		vectors = append(vectors, falconMindlapseVector{
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
	if len(vectors) != 10000 {
		t.Fatalf("loaded %d vectors, want 10000", len(vectors))
	}
	return vectors
}

func mustDecodeMindlapseHex(t *testing.T, s string) []byte {
	t.Helper()
	out, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("invalid hex: %v", err)
	}
	return out
}

func verifyFalconMindlapseVector(t *testing.T, msg, pk, sig []byte) bool {
	t.Helper()

	hashInput := make([]byte, falconHashToPointInputSize)
	copy(hashInput[:falconMsgSize], msg)
	copy(hashInput[falconMsgSize:], sig)
	challenge, err := (&falconHashToPointShake256{}).Run(hashInput)
	if err != nil {
		t.Fatal(err)
	}

	coreInput := make([]byte, falconCoreInputSize)
	copy(coreInput[:falconSigSize], sig)
	copy(coreInput[falconSigSize:falconSigSize+falconPKSize], pk)
	copy(coreInput[falconSigSize+falconPKSize:], challenge)
	ret, err := (&falconCore{}).Run(coreInput)
	if err != nil {
		t.Fatal(err)
	}
	return bytes.Equal(ret, true32Byte)
}

func TestFalconMindlapseKAT(t *testing.T) {
	vectors := loadFalconMindlapseVectors(t)
	for _, v := range vectors {
		if !verifyFalconMindlapseVector(t, v.msg, v.pk, v.sig) {
			t.Fatalf("vector %d: verification failed", v.count)
		}
	}
	t.Logf("%d vectors returned true", len(vectors))
}

func TestFalconMindlapseKATTampered(t *testing.T) {
	vectors := loadFalconMindlapseVectors(t)
	for _, v := range vectors[:10] {
		sig := append([]byte(nil), v.sig...)
		sig[len(sig)-1] ^= 0x01
		if verifyFalconMindlapseVector(t, v.msg, v.pk, sig) {
			t.Fatalf("vector %d: tampered signature verified", v.count)
		}
	}
	t.Log("10 tampered vectors returned false")
}

func TestFalconMindlapseKATWrongKey(t *testing.T) {
	vectors := loadFalconMindlapseVectors(t)
	for i, v := range vectors[:10] {
		wrongKey := vectors[i+1].pk
		if verifyFalconMindlapseVector(t, v.msg, wrongKey, v.sig) {
			t.Fatalf("vector %d: wrong public key verified", v.count)
		}
	}
	t.Log("10 wrong-key vectors returned false")
}

func TestFalconMindlapseKATWrongMsg(t *testing.T) {
	vectors := loadFalconMindlapseVectors(t)
	for _, v := range vectors[:10] {
		msg := append([]byte(nil), v.msg...)
		msg[0] ^= 0x01
		if verifyFalconMindlapseVector(t, msg, v.pk, v.sig) {
			t.Fatalf("vector %d: wrong message verified", v.count)
		}
	}
	t.Log("10 wrong-message vectors returned false")
}

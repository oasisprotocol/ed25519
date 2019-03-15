// Copyright (c) 2019 Oasis Labs Inc.  All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//   * Redistributions of source code must retain the above copyright
// notice, this list of conditions and the following disclaimer.
//    * Redistributions in binary form must reproduce the above
// copyright notice, this list of conditions and the following disclaimer
// in the documentation and/or other materials provided with the
// distribution.
//    * Neither the name of Oasis Labs Inc. nor the names of its
// contributors may be used to endorse or promote products derived from
// this software without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
// A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
// OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
// SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
// LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
// OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

package ed25519

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"io"
	"math/bits"
	"testing"
)

type batchTest int

const (
	batchNoErrors batchTest = iota
	batchWrongMessage
	batchWrongPk
	batchWrongSig

	batchCount    = 64
	badBatchCount = 96
)

// y coordinate of the final point from 'amd64-51-30k' with the same random generator
var batchVerifyY = [32]byte{
	0x51, 0xe7, 0x68, 0xe0, 0xf7, 0xa1, 0x88, 0x45, 0xde, 0xa1, 0xcb, 0xd9, 0x37, 0xd4, 0x78, 0x53,
	0x1b, 0x95, 0xdb, 0xbe, 0x66, 0x59, 0x29, 0x3b, 0x94, 0x51, 0x2f, 0xbc, 0x0d, 0x66, 0xba, 0x3f,
}

func testBatchInit(tb testing.TB, r io.Reader, batchSize int) ([]PublicKey, [][]byte, [][]byte) {
	sks := make([]PrivateKey, batchSize)
	pks := make([]PublicKey, batchSize)
	sigs := make([][]byte, batchSize)
	messages := make([][]byte, batchSize)

	// generate keys
	for i := 0; i < batchSize; i++ {
		pub, priv, err := GenerateKey(r)
		if err != nil {
			tb.Fatalf("failed to generate key #%d: %v", i, err)
		}

		sks[i], pks[i] = priv, pub
	}

	// generate messages
	for i := 0; i < batchSize; i++ {
		// Yes, this generates too much, but the amount read from r needs
		// to match what was used to generate the good final y coord.
		m := make([]byte, 128)
		if _, err := io.ReadFull(r, m); err != nil {
			tb.Fatalf("failed to generate message #%d: %v", i, err)
		}
		mLen := (i & 127) + 1
		messages[i] = m[:mLen]
	}

	// sign messages
	for i := 0; i < batchSize; i++ {
		sigs[i] = Sign(sks[i], messages[i])
	}

	return pks, sigs, messages
}

func testBatchInstance(t *testing.T, tst batchTest, r io.Reader, batchSize int) {
	pks, sigs, messages := testBatchInit(t, r, batchSize)

	// mess things up (if required)
	var expectedRet bool
	switch tst {
	case batchNoErrors:
		expectedRet = true
	case batchWrongMessage:
		messages[0] = messages[1]
	case batchWrongPk:
		pks[0] = pks[1]
	case batchWrongSig:
		sigs[0] = sigs[1]
	}

	// Ensure the 0th signature verification will actually fail.
	sigOk := Verify(pks[0], messages[0], sigs[0])
	if sigOk != expectedRet {
		t.Fatalf("failed to force failure: %v", tst)
	}

	// verify the batch
	ok, valid, err := VerifyBatch(r, pks[:], messages[:], sigs[:])
	if err != nil {
		t.Fatalf("failed to verify batch: %v", err)
	}

	// validate the results
	if ok != expectedRet {
		t.Errorf("unexpected batch return code: %v (expected: %v)", ok, expectedRet)
	}
	if len(valid) != batchSize {
		t.Errorf("unexpected batch validity vector length: %v (expected: %v)", len(valid), batchSize)
	}
	for i, v := range valid {
		expectedValid := expectedRet
		if i != 0 {
			// The negative tests only mess up the 0th entry.
			expectedValid = true
		}
		if v != expectedValid {
			t.Errorf("unexpected batch element return code #%v: %v (expected: %v)", i, v, expectedValid)
		}
	}
}

func TestVerifyBatch(t *testing.T) {
	testBatchSaveY = true

	var drbg isaacpDrbg
	t.Run("NoErrors", func(t *testing.T) { testBatchInstance(t, batchNoErrors, &drbg, batchCount) })
	if !bytes.Equal(batchVerifyY[:], testBatchY[:]) {
		t.Fatalf("unexpected final y coordinate: %v (expected: %v)", hex.EncodeToString(testBatchY[:]), hex.EncodeToString(batchVerifyY[:]))
	}

	const nrFailTestRuns = 4
	t.Run("WrongMessage", func(t *testing.T) {
		for i := 0; i < nrFailTestRuns; i++ {
			testBatchInstance(t, batchWrongMessage, rand.Reader, badBatchCount)
		}
	})
	t.Run("WrongPublicKey", func(t *testing.T) {
		for i := 0; i < nrFailTestRuns; i++ {
			testBatchInstance(t, batchWrongPk, rand.Reader, badBatchCount)
		}
	})
	t.Run("WrongSignature", func(t *testing.T) {
		for i := 0; i < nrFailTestRuns; i++ {
			testBatchInstance(t, batchWrongSig, rand.Reader, badBatchCount)
		}
	})
}

func BenchmarkVerifyBatch64(b *testing.B) {
	pks, sigs, messages := testBatchInit(b, rand.Reader, batchCount)
	testBatchSaveY = false
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		ok, _, _ := VerifyBatch(nil, pks[:], messages[:], sigs[:])
		if !ok {
			b.Fatalf("unexpected batch verification failure!")
		}
	}
}

type isaacpDrbg struct {
	state   [256]uint32
	buffer  [1024]byte
	a, b, c uint32
	left    int

	initialized bool
}

func (r *isaacpDrbg) mix() {
	a, b, c := r.a, r.b, r.c

	c = c + 1
	b = b + c

	for i := 0; i < 256; i += 4 {
		step := func(offset int, mix uint32) {
			x := r.state[i+offset]
			a = (a ^ mix) + r.state[(i+offset+128)&0xff]
			y := (a ^ b) + r.state[(x>>2)&0xff]
			r.state[i+offset] = y
			b = (x + a) ^ r.state[(y>>10)&0xff]
			binary.LittleEndian.PutUint32(r.buffer[(i+offset)*4:], b)
		}

		step(0, bits.RotateLeft32(a, 13))
		step(1, bits.RotateLeft32(a, -6))
		step(2, bits.RotateLeft32(a, 2))
		step(3, bits.RotateLeft32(a, -16))
	}

	r.a, r.b, r.c = a, b, c
	r.left = 1024
}

func (r *isaacpDrbg) random(p []byte) {
	var (
		idx  int
		pLen = len(p)
	)

	for pLen > 0 {
		use := r.left
		if pLen < use {
			use = pLen
		}

		bOff := len(r.buffer) - r.left
		copy(p[idx:], r.buffer[bOff:bOff+use])

		r.left -= use
		idx += use
		pLen -= use

		if r.left == 0 {
			r.mix()
		}
	}
}

func (r *isaacpDrbg) Read(buf []byte) (int, error) {
	if !r.initialized {
		r.mix()
		r.mix()
		r.initialized = true
	}

	r.random(buf)

	return len(buf), nil
}

// Copyright (c) 2016 The Go Authors. All rights reserved.
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
//    * Neither the name of Google Inc. nor the names of its
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

package x25519

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/oasisprotocol/ed25519"
)

const expectedHex = "89161fde887b2b53de549af483940106ecc114d6982daa98256de23bdf77661a"

// lowOrderPoints from libsodium.
// https://github.com/jedisct1/libsodium/blob/65621a1059a37d/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c#L11-L70
var lowOrderPoints = [][]byte{
	{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	{0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
	{0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00},
	{0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57},
	{0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	{0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
	{0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f},
}

// result of the curve25519 scalarmult ((|255| * basepoint) * basepoint)... 1024 times
var curved25519Expected = [32]byte{
	0xac, 0xce, 0x24, 0xb1, 0xd4, 0xa2, 0x36, 0x21,
	0x15, 0xe2, 0x3e, 0x84, 0x3c, 0x23, 0x2b, 0x5f,
	0x95, 0x6c, 0xc0, 0x7b, 0x95, 0x82, 0xd7, 0x93,
	0xd5, 0x19, 0xb6, 0xf1, 0xfb, 0x96, 0xd6, 0x04,
}

func TestScalarBaseMult(t *testing.T) {
	csk := [2][32]byte{
		{255},
	}

	for i := 0; i < 1024; i++ {
		ScalarBaseMult(&csk[(i&1)^1], &csk[i&1])
	}

	if !bytes.Equal(curved25519Expected[:], csk[0][:]) {
		t.Fatal("scalarmult ((|255| * basepoint) * basepoint)... 1024 did not match")
	}
}

func BenchmarkScalarBaseMult(b *testing.B) {
	var in, out [32]byte
	in[0] = 1

	b.SetBytes(32)
	for i := 0; i < b.N; i++ {
		ScalarBaseMult(&out, &in)
	}
}

func TestX25519Basepoint(t *testing.T) {
	x := make([]byte, 32)
	x[0] = 1

	for i := 0; i < 200; i++ {
		var err error
		x, err = X25519(x, Basepoint)
		if err != nil {
			t.Fatal(err)
		}
	}

	result := fmt.Sprintf("%x", x)
	if result != expectedHex {
		t.Errorf("incorrect result: got %s, want %s", result, expectedHex)
	}
}

func TestLowOrderPoints(t *testing.T) {
	scalar := make([]byte, ScalarSize)
	if _, err := rand.Read(scalar); err != nil {
		t.Fatal(err)
	}
	for i, p := range lowOrderPoints {
		out, err := X25519(scalar, p)
		if err == nil {
			t.Errorf("%d: expected error, got nil", i)
		}
		if out != nil {
			t.Errorf("%d: expected nil output, got %x", i, out)
		}
	}
}

func TestX25519Conversion(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)

	xPrivate := EdPrivateKeyToX25519(private)
	xPublic, err := X25519(xPrivate, Basepoint)
	if err != nil {
		t.Errorf("X25519(xPrivate, Basepoint): %v", err)
	}

	xPublic2, ok := EdPublicKeyToX25519(public)
	if !ok {
		t.Errorf("EdPublicKeyToX25519(public): failed")
	}

	if !bytes.Equal(xPublic, xPublic2) {
		t.Errorf("Values didn't match: curve25519 produced %x, conversion produced %x", xPublic, xPublic2)
	}
}

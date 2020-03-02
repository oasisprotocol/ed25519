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

// Package x25519 provides an implementation of the X25519 function, which
// performs scalar multiplication on the elliptic curve known as Curve25519.
// See RFC 7748.
package x25519

import (
	"crypto/sha512"
	"crypto/subtle"
	"fmt"

	xcurve "golang.org/x/crypto/curve25519"

	"github.com/oasislabs/ed25519"
	"github.com/oasislabs/ed25519/internal/curve25519"
	"github.com/oasislabs/ed25519/internal/ge25519"
	"github.com/oasislabs/ed25519/internal/modm"
)

const (
	// ScalarSize is the size of the scalar input to X25519.
	ScalarSize = 32
	// PointSize is the size of the point input to X25519.
	PointSize = 32
)

// Basepoint is the canonical Curve25519 generator.
var Basepoint []byte

var basePoint = [32]byte{9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

// ScalarMult sets dst to the product in*base where dst and base are the x
// coordinates of group points and all values are in little-endian form.
//
// Deprecated: when provided a low-order point, ScalarMult will set dst to all
// zeroes, irrespective of the scalar. Instead, use the X25519 function, which
// will return an error.
func ScalarMult(dst, in, base *[32]byte) {
	xcurve.ScalarMult(dst, in, base)
}

// ScalarBaseMult sets dst to the product in*base where dst and base are
// the x coordinates of group points, base is the standard generator and
// all values are in little-endian form.
//
// It is recommended to use the X25519 function with Basepoint instead, as
// copying into fixed size arrays can lead to unexpected bugs.
func ScalarBaseMult(dst, in *[32]byte) {
	// ED25519_FN(curved25519_scalarmult_basepoint) (curved25519_key pk, const curved25519_key e)
	var (
		ec              [32]byte
		s               modm.Bignum256
		p               ge25519.Ge25519
		yplusz, zminusy curve25519.Bignum25519
	)

	// clamp
	copy(ec[:], in[:])
	ec[0] &= 248
	ec[31] &= 127
	ec[31] |= 64

	modm.ExpandRaw(&s, ec[:])

	// scalar * basepoint
	ge25519.ScalarmultBaseNiels(&p, &ge25519.NielsBaseMultiples, &s)

	// u = (y + z) / (z - y)
	curve25519.Add(&yplusz, p.Y(), p.Z())
	curve25519.Sub(&zminusy, p.Z(), p.Y())
	curve25519.Recip(&zminusy, &zminusy)
	curve25519.Mul(&yplusz, &yplusz, &zminusy)
	curve25519.Contract(dst[:], &yplusz)

	s.Reset()
	for i := range ec {
		ec[i] = 0
	}
}

// X25519 returns the result of the scalar multiplication (scalar * point),
// according to RFC 7748, Section 5. scalar, point and the return value are
// slices of 32 bytes.
//
// scalar can be generated at random, for example with crypto/rand. point should
// be either Basepoint or the output of another X25519 call.
//
// If point is Basepoint (but not if it's a different slice with the same
// contents) a precomputed implementation might be used for performance.
func X25519(scalar, point []byte) ([]byte, error) {
	// Outline the body of function, to let the allocation be inlined in the
	// caller, and possibly avoid escaping to the heap.
	var dst [32]byte
	return x25519(&dst, scalar, point)
}

func x25519(dst *[32]byte, scalar, point []byte) ([]byte, error) {
	var in [32]byte
	if l := len(scalar); l != 32 {
		return nil, fmt.Errorf("bad scalar length: %d, expected %d", l, 32)
	}
	if l := len(point); l != 32 {
		return nil, fmt.Errorf("bad point length: %d, expected %d", l, 32)
	}
	copy(in[:], scalar)
	if &point[0] == &Basepoint[0] {
		checkBasepoint()
		ScalarBaseMult(dst, &in)
	} else {
		var base, zero [32]byte
		copy(base[:], point)
		ScalarMult(dst, &in, &base)
		if subtle.ConstantTimeCompare(dst[:], zero[:]) == 1 {
			return nil, fmt.Errorf("bad input point: low order point")
		}
	}
	return dst[:], nil
}

func checkBasepoint() {
	if subtle.ConstantTimeCompare(Basepoint, []byte{
		0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}) != 1 {
		panic("curve25519: global Basepoint value was modified")
	}
}

// EdPrivateKeyToX25519 converts an Ed25519 private key into a corresponding
// X25519 private key such that the resulting X25519 public key will equal
// the result from EdPublicKeyToX25519.
func EdPrivateKeyToX25519(privateKey ed25519.PrivateKey) []byte {
	h := sha512.New()
	_, _ = h.Write(privateKey[:32])
	digest := h.Sum(nil)
	h.Reset()

	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64

	dst := make([]byte, ScalarSize)
	copy(dst, digest)

	return dst
}

func curve25519One(z *curve25519.Bignum25519) {
	z.Reset()
	z[0] = 1
}

func edwardsToMontgomeryX(outX, y *curve25519.Bignum25519) {
	// We only need the x-coordinate of the curve25519 point, which I'll
	// call u. The isomorphism is u=(y+1)/(1-y), since y=Y/Z, this gives
	// u=(Y+Z)/(Z-Y). We know that Z=1, thus u=(Y+1)/(1-Y).
	var oneMinusY curve25519.Bignum25519
	curve25519One(&oneMinusY)
	curve25519.Sub(&oneMinusY, &oneMinusY, y)
	curve25519.Recip(&oneMinusY, &oneMinusY)

	curve25519One(outX)
	curve25519.Add(outX, outX, y)

	curve25519.Mul(outX, outX, &oneMinusY)
}

// EdPublicKeyToX25519 converts an Ed25519 public key into the X25519 public
// key that would be generated from the same private key.
func EdPublicKeyToX25519(publicKey ed25519.PublicKey) ([]byte, bool) {
	// Negate a copy of the public key, due to UnpackNegativeVartime.
	var pkCopy [32]byte
	copy(pkCopy[:], publicKey)
	pkCopy[31] ^= (1 << 7)

	var A ge25519.Ge25519
	if !ge25519.UnpackNegativeVartime(&A, pkCopy[:]) {
		return nil, false
	}

	// A.Z = 1 as a postcondition of UnpackNegativeVartime.
	var x curve25519.Bignum25519
	edwardsToMontgomeryX(&x, A.Y())
	dst := make([]byte, PointSize)
	curve25519.Contract(dst, &x)

	return dst, true
}

func init() {
	Basepoint = basePoint[:]
}

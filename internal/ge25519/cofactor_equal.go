// Copyright (c) 2009 The Go Authors. All rights reserved.
// Copyright (c) 2020 Henry de Valence. All rights reserved.
// Copyright (c) 2020 Oasis Labs Inc.  All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//    * Redistributions of source code must retain the above copyright
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

package ge25519

import (
	"bytes"

	"github.com/oasisprotocol/ed25519/internal/curve25519"
)

// At some point to reduce my frustration and increase my sanity, I should
// just port ed25519-dalek to Go or something, instead of having to deal
// with a mess of ref10 derivatives every single time.
//
// For now, shamelessly steal the CofactorEqual routine from:
// https://github.com/hdevalence/ed25519consensus/blob/main/internal/edwards25519/edwards25519.go

func geSub(r *ge25519p1p1, p *Ge25519, q *ge25519pniels) {
	var t0 curve25519.Bignum25519

	curve25519.Add(&r.x, &p.y, &p.x)
	curve25519.Sub(&r.y, &p.y, &p.x)
	curve25519.Mul(&r.z, &r.x, &q.ysubx)
	curve25519.Mul(&r.y, &r.y, &q.xaddy)
	curve25519.Mul(&r.t, &q.t2d, &p.t)
	curve25519.Mul(&r.x, &p.z, &q.z)
	curve25519.Add(&t0, &r.x, &r.x)
	curve25519.Sub(&r.x, &r.z, &r.y)
	curve25519.Add(&r.y, &r.z, &r.y)
	curve25519.Sub(&r.z, &t0, &r.t)
	curve25519.Add(&r.t, &t0, &r.t)
}

// ProjectiveToExtended converts p from a projective group element to an
// extended group element.
func ProjectiveToExtended(r, p *Ge25519) {
	curve25519.Mul(&r.x, &p.x, &p.z)
	curve25519.Mul(&r.y, &p.y, &p.z)
	curve25519.Square(&r.z, &p.z)
	curve25519.Mul(&r.t, &p.x, &p.y)
}

// CofactorEqual checks whether p, q are equal up to cofactor multiplication
// (ie. if their difference is of small order).
func CofactorEqual(p, q *Ge25519) bool {
	var t1 ge25519pniels
	var t2 ge25519p1p1
	var t3 Ge25519

	fullToPniels(&t1, q)
	geSub(&t2, p, &t1)         // t2 = (P - Q)
	p1p1ToFull(&t3, &t2)       // t3 = (P - Q)
	CofactorMultiply(&t3, &t3) // t3 = [8](P-Q)

	// Now we want to check whether the point t3 is the identity.
	// In projective coordinates this is (X:Y:Z) ~ (0:1:0)
	// ie. X/Z = 0, Y/Z = 1
	// <=> X = 0, Y = Z

	var zero [32]byte
	var xBytes [32]byte
	var yBytes [32]byte
	var zBytes [32]byte

	curve25519.Contract(xBytes[:], &t3.x)
	curve25519.Contract(yBytes[:], &t3.y)
	curve25519.Contract(zBytes[:], &t3.z)

	return bytes.Equal(zero[:], xBytes[:]) && bytes.Equal(yBytes[:], zBytes[:])
}

// CofactorMultiply multiplies the full group element by the cofactor (8).
func CofactorMultiply(r, p *Ge25519) {
	var t1 ge25519p1p1
	var t2 Ge25519

	doubleP1p1(&t1, p)   // t1 = [2]P
	p1p1ToFull(&t2, &t1) // t2 = [2]P
	doubleP1p1(&t1, &t2) // t1 = [4]P
	p1p1ToFull(&t2, &t1) // t2 = [4]P
	doubleP1p1(&t1, &t2) // t1 = [8]P
	p1p1ToFull(r, &t1)   // r  = [8]P
}

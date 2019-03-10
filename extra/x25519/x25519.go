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

// Package x25519 provides an implementation of scalar multiplication on
// the elliptic curve known as curve25519. See https://cr.yp.to/ecdh.html
package x25519

import (
	xcurve "golang.org/x/crypto/curve25519"

	"github.com/oasislabs/ed25519/internal/curve25519"
	"github.com/oasislabs/ed25519/internal/ge25519"
	"github.com/oasislabs/ed25519/internal/modm"
)

// ScalarMult sets dst to the product in*base where dst and base are the x
// coordinates of group points and all values are in little-endian form.
func ScalarMult(dst, in, base *[32]byte) {
	xcurve.ScalarMult(dst, in, base)
}

// ScalarBaseMult sets dst to the product in*base where dst and base are
// the x coordinates of group points, base is the standard generator and
// all values are in little-endian form.
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
}

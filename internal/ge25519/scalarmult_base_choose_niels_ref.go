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

// +build !amd64,noasm

package ge25519

import "github.com/oasislabs/ed25519/internal/curve25519"

func windowbEqual(b, c uint32) uint32 {
	// uint32_t ge25519_windowb_equal(uint32_t b, uint32_t c)
	return ((b ^ c) - 1) >> 31
}

func scalarmultBaseChooseNiels(t *ge25519niels, table *[256][96]byte, pos int, b int8) {
	// ge25519_scalarmult_base_choose_niels(ge25519_niels *t, const uint8_t table[256][96], uint32_t pos, signed char b)
	var (
		neg  curve25519.Bignum25519
		sign = uint32(uint8(b) >> 7)
		mask = ^(sign - 1)
		u    = (uint32(b) + mask) ^ mask
	)

	// ysubx, xaddy, t2d in packed form. initialize to ysubx = 1, xaddy = 1, t2d = 0
	var packed [96]byte
	packed[0] = 1
	packed[32] = 1

	for i := 0; i < 8; i++ {
		moveConditionalBytes(&packed, &table[(pos*8)+i], uint64(windowbEqual(u, uint32(i+1))))
	}

	// expand in to t
	curve25519.Expand(&t.ysubx, packed[0:])
	curve25519.Expand(&t.xaddy, packed[32:])
	curve25519.Expand(&t.t2d, packed[64:])

	// adjust for sign
	curve25519.SwapConditional(&t.ysubx, &t.xaddy, uint64(sign))
	curve25519.Neg(&neg, &t.t2d)
	curve25519.SwapConditional(&t.t2d, &neg, uint64(sign))
}

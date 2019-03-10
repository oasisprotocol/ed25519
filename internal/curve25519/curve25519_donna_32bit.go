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

// +build !amd64

package curve25519

import "encoding/binary"

// Upstream: `curve25519-donna-32bit.h`

const (
	reduceMask25 = (uint32(1) << 25) - 1
	reduceMask26 = (uint32(1) << 26) - 1

	twoP0      = 0x07ffffda
	twoP13579  = 0x03fffffe
	twoP2468   = 0x07fffffe
	fourP0     = 0x0fffffb4
	fourP13579 = 0x07fffffc
	fourP2468  = 0x0ffffffc
)

type Bignum25519 [10]uint32

func (out *Bignum25519) Reset() {
	for i := range out {
		out[i] = 0
	}
}

func Copy(out, in *Bignum25519) {
	out[0] = in[0]
	out[1] = in[1]
	out[2] = in[2]
	out[3] = in[3]
	out[4] = in[4]
	out[5] = in[5]
	out[6] = in[6]
	out[7] = in[7]
	out[8] = in[8]
	out[9] = in[9]
}

func Add(out, a, b *Bignum25519) {
	out[0] = a[0] + b[0]
	out[1] = a[1] + b[1]
	out[2] = a[2] + b[2]
	out[3] = a[3] + b[3]
	out[4] = a[4] + b[4]
	out[5] = a[5] + b[5]
	out[6] = a[6] + b[6]
	out[7] = a[7] + b[7]
	out[8] = a[8] + b[8]
	out[9] = a[9] + b[9]
}

func AddAfterBasic(out, a, b *Bignum25519) {
	out[0] = a[0] + b[0]
	c := (out[0] >> 26)
	out[0] &= reduceMask26

	out[1] = a[1] + b[1] + c
	c = (out[1] >> 25)
	out[1] &= reduceMask25

	out[2] = a[2] + b[2] + c
	c = (out[2] >> 26)
	out[2] &= reduceMask26

	out[3] = a[3] + b[3] + c
	c = (out[3] >> 25)
	out[3] &= reduceMask25

	out[4] = a[4] + b[4] + c
	c = (out[4] >> 26)
	out[4] &= reduceMask26

	out[5] = a[5] + b[5] + c
	c = (out[5] >> 25)
	out[5] &= reduceMask25

	out[6] = a[6] + b[6] + c
	c = (out[6] >> 26)
	out[6] &= reduceMask26

	out[7] = a[7] + b[7] + c
	c = (out[7] >> 25)
	out[7] &= reduceMask25

	out[8] = a[8] + b[8] + c
	c = (out[8] >> 26)
	out[8] &= reduceMask26

	out[9] = a[9] + b[9] + c
	c = (out[9] >> 25)
	out[9] &= reduceMask25

	out[0] += 19 * c
}

func AddReduce(out, a, b *Bignum25519) {
	out[0] = a[0] + b[0]
	c := (out[0] >> 26)
	out[0] &= reduceMask26

	out[1] = a[1] + b[1] + c
	c = (out[1] >> 25)
	out[1] &= reduceMask25

	out[2] = a[2] + b[2] + c
	c = (out[2] >> 26)
	out[2] &= reduceMask26

	out[3] = a[3] + b[3] + c
	c = (out[3] >> 25)
	out[3] &= reduceMask25

	out[4] = a[4] + b[4] + c
	c = (out[4] >> 26)
	out[4] &= reduceMask26

	out[5] = a[5] + b[5] + c
	c = (out[5] >> 25)
	out[5] &= reduceMask25

	out[6] = a[6] + b[6] + c
	c = (out[6] >> 26)
	out[6] &= reduceMask26

	out[7] = a[7] + b[7] + c
	c = (out[7] >> 25)
	out[7] &= reduceMask25

	out[8] = a[8] + b[8] + c
	c = (out[8] >> 26)
	out[8] &= reduceMask26

	out[9] = a[9] + b[9] + c
	c = (out[9] >> 25)
	out[9] &= reduceMask25

	out[0] += 19 * c
}

func Sub(out, a, b *Bignum25519) {
	out[0] = twoP0 + a[0] - b[0]
	c := (out[0] >> 26)
	out[0] &= reduceMask26

	out[1] = twoP13579 + a[1] - b[1] + c
	c = (out[1] >> 25)
	out[1] &= reduceMask25

	out[2] = twoP2468 + a[2] - b[2] + c
	c = (out[2] >> 26)
	out[2] &= reduceMask26

	out[3] = twoP13579 + a[3] - b[3] + c
	c = (out[3] >> 25)
	out[3] &= reduceMask25

	out[4] = twoP2468 + a[4] - b[4] + c

	out[5] = twoP13579 + a[5] - b[5]

	out[6] = twoP2468 + a[6] - b[6]

	out[7] = twoP13579 + a[7] - b[7]

	out[8] = twoP2468 + a[8] - b[8]

	out[9] = twoP13579 + a[9] - b[9]
}

func SubAfterBasic(out, a, b *Bignum25519) {
	out[0] = fourP0 + a[0] - b[0]
	c := (out[0] >> 26)
	out[0] &= reduceMask26

	out[1] = fourP13579 + a[1] - b[1] + c
	c = (out[1] >> 25)
	out[1] &= reduceMask25

	out[2] = fourP2468 + a[2] - b[2] + c
	c = (out[2] >> 26)
	out[2] &= reduceMask26

	out[3] = fourP13579 + a[3] - b[3] + c
	c = (out[3] >> 25)
	out[3] &= reduceMask25

	out[4] = fourP2468 + a[4] - b[4] + c
	c = (out[4] >> 26)
	out[4] &= reduceMask26

	out[5] = fourP13579 + a[5] - b[5] + c
	c = (out[5] >> 25)
	out[5] &= reduceMask25

	out[6] = fourP2468 + a[6] - b[6] + c
	c = (out[6] >> 26)
	out[6] &= reduceMask26

	out[7] = fourP13579 + a[7] - b[7] + c
	c = (out[7] >> 25)
	out[7] &= reduceMask25

	out[8] = fourP2468 + a[8] - b[8] + c
	c = (out[8] >> 26)
	out[8] &= reduceMask26

	out[9] = fourP13579 + a[9] - b[9] + c
	c = (out[9] >> 25)
	out[9] &= reduceMask25

	out[0] += 19 * c
}

func SubReduce(out, a, b *Bignum25519) {
	out[0] = fourP0 + a[0] - b[0]
	c := (out[0] >> 26)
	out[0] &= reduceMask26

	out[1] = fourP13579 + a[1] - b[1] + c
	c = (out[1] >> 25)
	out[1] &= reduceMask25

	out[2] = fourP2468 + a[2] - b[2] + c
	c = (out[2] >> 26)
	out[2] &= reduceMask26

	out[3] = fourP13579 + a[3] - b[3] + c
	c = (out[3] >> 25)
	out[3] &= reduceMask25

	out[4] = fourP2468 + a[4] - b[4] + c
	c = (out[4] >> 26)
	out[4] &= reduceMask26

	out[5] = fourP13579 + a[5] - b[5] + c
	c = (out[5] >> 25)
	out[5] &= reduceMask25

	out[6] = fourP2468 + a[6] - b[6] + c
	c = (out[6] >> 26)
	out[6] &= reduceMask26

	out[7] = fourP13579 + a[7] - b[7] + c
	c = (out[7] >> 25)
	out[7] &= reduceMask25

	out[8] = fourP2468 + a[8] - b[8] + c
	c = (out[8] >> 26)
	out[8] &= reduceMask26

	out[9] = fourP13579 + a[9] - b[9] + c
	c = (out[9] >> 25)
	out[9] &= reduceMask25

	out[0] += 19 * c
}

func Neg(out, a *Bignum25519) {
	out[0] = twoP0 - a[0]
	c := (out[0] >> 26)
	out[0] &= reduceMask26

	out[1] = twoP13579 - a[1] + c
	c = (out[1] >> 25)
	out[1] &= reduceMask25

	out[2] = twoP2468 - a[2] + c
	c = (out[2] >> 26)
	out[2] &= reduceMask26

	out[3] = twoP13579 - a[3] + c
	c = (out[3] >> 25)
	out[3] &= reduceMask25

	out[4] = twoP2468 - a[4] + c
	c = (out[4] >> 26)
	out[4] &= reduceMask26

	out[5] = twoP13579 - a[5] + c
	c = (out[5] >> 25)
	out[5] &= reduceMask25

	out[6] = twoP2468 - a[6] + c
	c = (out[6] >> 26)
	out[6] &= reduceMask26

	out[7] = twoP13579 - a[7] + c
	c = (out[7] >> 25)
	out[7] &= reduceMask25

	out[8] = twoP2468 - a[8] + c
	c = (out[8] >> 26)
	out[8] &= reduceMask26

	out[9] = twoP13579 - a[9] + c
	c = (out[9] >> 25)
	out[9] &= reduceMask25

	out[0] += 19 * c
}

func Mul(out, a, b *Bignum25519) {
	var m0, m1, m2, m3, m4, m5, m6, m7, m8, m9 uint64

	r0, r1, r2, r3, r4, r5, r6, r7, r8, r9 := b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9]
	s0, s1, s2, s3, s4, s5, s6, s7, s8, s9 := a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8], a[9]

	m1 = uint64(r0)*uint64(s1) + uint64(r1)*uint64(s0)
	m3 = uint64(r0)*uint64(s3) + uint64(r1)*uint64(s2) + uint64(r2)*uint64(s1) + uint64(r3)*uint64(s0)
	m5 = uint64(r0)*uint64(s5) + uint64(r1)*uint64(s4) + uint64(r2)*uint64(s3) + uint64(r3)*uint64(s2) + uint64(r4)*uint64(s1) + uint64(r5)*uint64(s0)
	m7 = uint64(r0)*uint64(s7) + uint64(r1)*uint64(s6) + uint64(r2)*uint64(s5) + uint64(r3)*uint64(s4) + uint64(r4)*uint64(s3) + uint64(r5)*uint64(s2) + uint64(r6)*uint64(s1) + uint64(r7)*uint64(s0)
	m9 = uint64(r0)*uint64(s9) + uint64(r1)*uint64(s8) + uint64(r2)*uint64(s7) + uint64(r3)*uint64(s6) + uint64(r4)*uint64(s5) + uint64(r5)*uint64(s4) + uint64(r6)*uint64(s3) + uint64(r7)*uint64(s2) + uint64(r8)*uint64(s1) + uint64(r9)*uint64(s0)

	r1 *= 2
	r3 *= 2
	r5 *= 2
	r7 *= 2

	m0 = uint64(r0) * uint64(s0)
	m2 = uint64(r0)*uint64(s2) + uint64(r1)*uint64(s1) + uint64(r2)*uint64(s0)
	m4 = uint64(r0)*uint64(s4) + uint64(r1)*uint64(s3) + uint64(r2)*uint64(s2) + uint64(r3)*uint64(s1) + uint64(r4)*uint64(s0)
	m6 = uint64(r0)*uint64(s6) + uint64(r1)*uint64(s5) + uint64(r2)*uint64(s4) + uint64(r3)*uint64(s3) + uint64(r4)*uint64(s2) + uint64(r5)*uint64(s1) + uint64(r6)*uint64(s0)
	m8 = uint64(r0)*uint64(s8) + uint64(r1)*uint64(s7) + uint64(r2)*uint64(s6) + uint64(r3)*uint64(s5) + uint64(r4)*uint64(s4) + uint64(r5)*uint64(s3) + uint64(r6)*uint64(s2) + uint64(r7)*uint64(s1) + uint64(r8)*uint64(s0)

	r1 *= 19
	r2 *= 19
	r3 = (r3 / 2) * 19
	r4 *= 19
	r5 = (r5 / 2) * 19
	r6 *= 19
	r7 = (r7 / 2) * 19
	r8 *= 19
	r9 *= 19

	m1 += (uint64(r9)*uint64(s2) + uint64(r8)*uint64(s3) + uint64(r7)*uint64(s4) + uint64(r6)*uint64(s5) + uint64(r5)*uint64(s6) + uint64(r4)*uint64(s7) + uint64(r3)*uint64(s8) + uint64(r2)*uint64(s9))
	m3 += (uint64(r9)*uint64(s4) + uint64(r8)*uint64(s5) + uint64(r7)*uint64(s6) + uint64(r6)*uint64(s7) + uint64(r5)*uint64(s8) + uint64(r4)*uint64(s9))
	m5 += (uint64(r9)*uint64(s6) + uint64(r8)*uint64(s7) + uint64(r7)*uint64(s8) + uint64(r6)*uint64(s9))
	m7 += (uint64(r9)*uint64(s8) + uint64(r8)*uint64(s9))

	r3 *= 2
	r5 *= 2
	r7 *= 2
	r9 *= 2

	m0 += (uint64(r9)*uint64(s1) + uint64(r8)*uint64(s2) + uint64(r7)*uint64(s3) + uint64(r6)*uint64(s4) + uint64(r5)*uint64(s5) + uint64(r4)*uint64(s6) + uint64(r3)*uint64(s7) + uint64(r2)*uint64(s8) + uint64(r1)*uint64(s9))
	m2 += (uint64(r9)*uint64(s3) + uint64(r8)*uint64(s4) + uint64(r7)*uint64(s5) + uint64(r6)*uint64(s6) + uint64(r5)*uint64(s7) + uint64(r4)*uint64(s8) + uint64(r3)*uint64(s9))
	m4 += (uint64(r9)*uint64(s5) + uint64(r8)*uint64(s6) + uint64(r7)*uint64(s7) + uint64(r6)*uint64(s8) + uint64(r5)*uint64(s9))
	m6 += (uint64(r9)*uint64(s7) + uint64(r8)*uint64(s8) + uint64(r7)*uint64(s9))
	m8 += (uint64(r9) * uint64(s9))

	r0 = uint32(m0) & reduceMask26
	c := (m0 >> 26)

	m1 += c
	r1 = uint32(m1) & reduceMask25
	c = (m1 >> 25)

	m2 += c
	r2 = uint32(m2) & reduceMask26
	c = (m2 >> 26)

	m3 += c
	r3 = uint32(m3) & reduceMask25
	c = (m3 >> 25)

	m4 += c
	r4 = uint32(m4) & reduceMask26
	c = (m4 >> 26)

	m5 += c
	r5 = uint32(m5) & reduceMask25
	c = (m5 >> 25)

	m6 += c
	r6 = uint32(m6) & reduceMask26
	c = (m6 >> 26)

	m7 += c
	r7 = uint32(m7) & reduceMask25
	c = (m7 >> 25)

	m8 += c
	r8 = uint32(m8) & reduceMask26
	c = (m8 >> 26)

	m9 += c
	r9 = uint32(m9) & reduceMask25
	p := uint32(m9 >> 25)

	m0 = uint64(r0) + uint64(p)*19
	r0 = uint32(m0) & reduceMask26
	p = uint32(m0 >> 26)

	r1 += p

	out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7], out[8], out[9] = r0, r1, r2, r3, r4, r5, r6, r7, r8, r9
}

func SquareTimes(out, in *Bignum25519, count int) {
	var m0, m1, m2, m3, m4, m5, m6, m7, m8, m9 uint64

	r0, r1, r2, r3, r4, r5, r6, r7, r8, r9 := in[0], in[1], in[2], in[3], in[4], in[5], in[6], in[7], in[8], in[9]

	for i := 0; i < count; i++ {
		m0 = uint64(r0) * uint64(r0)
		r0 *= 2
		m1 = uint64(r0) * uint64(r1)
		m2 = uint64(r0)*uint64(r2) + uint64(r1)*uint64(r1*2)
		r1 *= 2
		m3 = uint64(r0)*uint64(r3) + uint64(r1)*uint64(r2)
		m4 = uint64(r0)*uint64(r4) + uint64(r1)*uint64(r3*2) + uint64(r2)*uint64(r2)
		r2 *= 2
		m5 = uint64(r0)*uint64(r5) + uint64(r1)*uint64(r4) + uint64(r2)*uint64(r3)
		m6 = uint64(r0)*uint64(r6) + uint64(r1)*uint64(r5*2) + uint64(r2)*uint64(r4) + uint64(r3)*uint64(r3*2)
		r3 *= 2
		m7 = uint64(r0)*uint64(r7) + uint64(r1)*uint64(r6) + uint64(r2)*uint64(r5) + uint64(r3)*uint64(r4)
		m8 = uint64(r0)*uint64(r8) + uint64(r1)*uint64(r7*2) + uint64(r2)*uint64(r6) + uint64(r3)*uint64(r5*2) + uint64(r4)*uint64(r4)
		m9 = uint64(r0)*uint64(r9) + uint64(r1)*uint64(r8) + uint64(r2)*uint64(r7) + uint64(r3)*uint64(r6) + uint64(r4)*uint64(r5*2)

		d6 := r6 * 19
		d7 := r7 * 2 * 19
		d8 := r8 * 19
		d9 := r9 * 2 * 19

		m0 += (uint64(d9)*uint64(r1) + uint64(d8)*uint64(r2) + uint64(d7)*uint64(r3) + uint64(d6)*uint64(r4*2) + uint64(r5)*uint64(r5*2*19))
		m1 += (uint64(d9)*uint64(r2/2) + uint64(d8)*uint64(r3) + uint64(d7)*uint64(r4) + uint64(d6)*uint64(r5*2))
		m2 += (uint64(d9)*uint64(r3) + uint64(d8)*uint64(r4*2) + uint64(d7)*uint64(r5*2) + uint64(d6)*uint64(r6))
		m3 += (uint64(d9)*uint64(r4) + uint64(d8)*uint64(r5*2) + uint64(d7)*uint64(r6))
		m4 += (uint64(d9)*uint64(r5*2) + uint64(d8)*uint64(r6*2) + uint64(d7)*uint64(r7))
		m5 += (uint64(d9)*uint64(r6) + uint64(d8)*uint64(r7*2))
		m6 += (uint64(d9)*uint64(r7*2) + uint64(d8)*uint64(r8))
		m7 += (uint64(d9) * uint64(r8))
		m8 += (uint64(d9) * uint64(r9))

		r0 = uint32(m0) & reduceMask26
		c := (m0 >> 26)

		m1 += c
		r1 = uint32(m1) & reduceMask25
		c = (m1 >> 25)

		m2 += c
		r2 = uint32(m2) & reduceMask26
		c = (m2 >> 26)

		m3 += c
		r3 = uint32(m3) & reduceMask25
		c = (m3 >> 25)

		m4 += c
		r4 = uint32(m4) & reduceMask26
		c = (m4 >> 26)

		m5 += c
		r5 = uint32(m5) & reduceMask25
		c = (m5 >> 25)

		m6 += c
		r6 = uint32(m6) & reduceMask26
		c = (m6 >> 26)

		m7 += c
		r7 = uint32(m7) & reduceMask25
		c = (m7 >> 25)

		m8 += c
		r8 = uint32(m8) & reduceMask26
		c = (m8 >> 26)

		m9 += c
		r9 = uint32(m9) & reduceMask25
		p := uint32(m9 >> 25)

		m0 = uint64(r0) + uint64(p)*19
		r0 = uint32(m0) & reduceMask26
		p = uint32(m0 >> 26)

		r1 += p
	}

	out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7], out[8], out[9] = r0, r1, r2, r3, r4, r5, r6, r7, r8, r9
}

func Square(out, in *Bignum25519) {
	var m0, m1, m2, m3, m4, m5, m6, m7, m8, m9 uint64

	r0, r1, r2, r3, r4, r5, r6, r7, r8, r9 := in[0], in[1], in[2], in[3], in[4], in[5], in[6], in[7], in[8], in[9]

	m0 = uint64(r0) * uint64(r0)
	r0 *= 2
	m1 = uint64(r0) * uint64(r1)
	m2 = uint64(r0)*uint64(r2) + uint64(r1)*uint64(r1*2)
	r1 *= 2
	m3 = uint64(r0)*uint64(r3) + uint64(r1)*uint64(r2)
	m4 = uint64(r0)*uint64(r4) + uint64(r1)*uint64(r3*2) + uint64(r2)*uint64(r2)
	r2 *= 2
	m5 = uint64(r0)*uint64(r5) + uint64(r1)*uint64(r4) + uint64(r2)*uint64(r3)
	m6 = uint64(r0)*uint64(r6) + uint64(r1)*uint64(r5*2) + uint64(r2)*uint64(r4) + uint64(r3)*uint64(r3*2)
	r3 *= 2
	m7 = uint64(r0)*uint64(r7) + uint64(r1)*uint64(r6) + uint64(r2)*uint64(r5) + uint64(r3)*uint64(r4)
	m8 = uint64(r0)*uint64(r8) + uint64(r1)*uint64(r7*2) + uint64(r2)*uint64(r6) + uint64(r3)*uint64(r5*2) + uint64(r4)*uint64(r4)
	m9 = uint64(r0)*uint64(r9) + uint64(r1)*uint64(r8) + uint64(r2)*uint64(r7) + uint64(r3)*uint64(r6) + uint64(r4)*uint64(r5*2)

	d6 := r6 * 19
	d7 := r7 * 2 * 19
	d8 := r8 * 19
	d9 := r9 * 2 * 19

	m0 += (uint64(d9)*uint64(r1) + uint64(d8)*uint64(r2) + uint64(d7)*uint64(r3) + uint64(d6)*uint64(r4*2) + uint64(r5)*uint64(r5*2*19))
	m1 += (uint64(d9)*uint64(r2/2) + uint64(d8)*uint64(r3) + uint64(d7)*uint64(r4) + uint64(d6)*uint64(r5*2))
	m2 += (uint64(d9)*uint64(r3) + uint64(d8)*uint64(r4*2) + uint64(d7)*uint64(r5*2) + uint64(d6)*uint64(r6))
	m3 += (uint64(d9)*uint64(r4) + uint64(d8)*uint64(r5*2) + uint64(d7)*uint64(r6))
	m4 += (uint64(d9)*uint64(r5*2) + uint64(d8)*uint64(r6*2) + uint64(d7)*uint64(r7))
	m5 += (uint64(d9)*uint64(r6) + uint64(d8)*uint64(r7*2))
	m6 += (uint64(d9)*uint64(r7*2) + uint64(d8)*uint64(r8))
	m7 += (uint64(d9) * uint64(r8))
	m8 += (uint64(d9) * uint64(r9))

	r0 = uint32(m0) & reduceMask26
	c := (m0 >> 26)

	m1 += c
	r1 = uint32(m1) & reduceMask25
	c = (m1 >> 25)

	m2 += c
	r2 = uint32(m2) & reduceMask26
	c = (m2 >> 26)

	m3 += c
	r3 = uint32(m3) & reduceMask25
	c = (m3 >> 25)

	m4 += c
	r4 = uint32(m4) & reduceMask26
	c = (m4 >> 26)

	m5 += c
	r5 = uint32(m5) & reduceMask25
	c = (m5 >> 25)

	m6 += c
	r6 = uint32(m6) & reduceMask26
	c = (m6 >> 26)

	m7 += c
	r7 = uint32(m7) & reduceMask25
	c = (m7 >> 25)

	m8 += c
	r8 = uint32(m8) & reduceMask26
	c = (m8 >> 26)

	m9 += c
	r9 = uint32(m9) & reduceMask25
	p := uint32(m9 >> 25)

	m0 = uint64(r0) + uint64(p)*19
	r0 = uint32(m0) & reduceMask26
	p = uint32(m0 >> 26)

	r1 += p

	out[0], out[1], out[2], out[3], out[4], out[5], out[6], out[7], out[8], out[9] = r0, r1, r2, r3, r4, r5, r6, r7, r8, r9
}

func Expand(out *Bignum25519, in []byte) {
	_ = in[31]
	x0 := binary.LittleEndian.Uint32(in[0:4])
	x1 := binary.LittleEndian.Uint32(in[4:8])
	x2 := binary.LittleEndian.Uint32(in[8:12])
	x3 := binary.LittleEndian.Uint32(in[12:16])
	x4 := binary.LittleEndian.Uint32(in[16:20])
	x5 := binary.LittleEndian.Uint32(in[20:24])
	x6 := binary.LittleEndian.Uint32(in[24:28])
	x7 := binary.LittleEndian.Uint32(in[28:32])

	out[0] = (x0) & 0x3ffffff

	out[1] = uint32(((uint64(x1)<<32)|uint64(x0))>>26) & 0x1ffffff

	out[2] = uint32(((uint64(x2)<<32)|uint64(x1))>>19) & 0x3ffffff

	out[3] = uint32(((uint64(x3)<<32)|uint64(x2))>>13) & 0x1ffffff

	out[4] = ((x3) >> 6) & 0x3ffffff

	out[5] = (x4) & 0x1ffffff

	out[6] = uint32(((uint64(x5)<<32)|uint64(x4))>>25) & 0x3ffffff

	out[7] = uint32(((uint64(x6)<<32)|uint64(x5))>>19) & 0x1ffffff

	out[8] = uint32(((uint64(x7)<<32)|uint64(x6))>>12) & 0x3ffffff

	out[9] = ((x7) >> 6) & 0x1ffffff
}

func Contract(out []byte, in *Bignum25519) {
	var f Bignum25519
	Copy(&f, in)

	contractCarry := func() {
		f[1] += f[0] >> 26
		f[0] &= reduceMask26

		f[2] += f[1] >> 25
		f[1] &= reduceMask25

		f[3] += f[2] >> 26
		f[2] &= reduceMask26

		f[4] += f[3] >> 25
		f[3] &= reduceMask25

		f[5] += f[4] >> 26
		f[4] &= reduceMask26

		f[6] += f[5] >> 25
		f[5] &= reduceMask25

		f[7] += f[6] >> 26
		f[6] &= reduceMask26

		f[8] += f[7] >> 25
		f[7] &= reduceMask25

		f[9] += f[8] >> 26
		f[8] &= reduceMask26
	}

	contractCarryFull := func() {
		contractCarry()

		f[0] += 19 * (f[9] >> 25)
		f[9] &= reduceMask25
	}

	contractCarryFinal := func() {
		contractCarry()

		f[9] &= reduceMask25
	}

	contractCarryFull()
	contractCarryFull()

	// now t is between 0 and 2^255-1, properly carried.
	// case 1: between 0 and 2^255-20. case 2: between 2^255-19 and 2^255-1.
	f[0] += 19
	contractCarryFull()

	// now between 19 and 2^255-1 in both cases, and offset by 19.
	f[0] += (reduceMask26 + 1) - 19
	f[1] += (reduceMask25 + 1) - 1
	f[2] += (reduceMask26 + 1) - 1
	f[3] += (reduceMask25 + 1) - 1
	f[4] += (reduceMask26 + 1) - 1
	f[5] += (reduceMask25 + 1) - 1
	f[6] += (reduceMask26 + 1) - 1
	f[7] += (reduceMask25 + 1) - 1
	f[8] += (reduceMask26 + 1) - 1
	f[9] += (reduceMask25 + 1) - 1

	// now between 2^255 and 2^256-20, and offset by 2^255.
	contractCarryFinal()

	f[1] <<= 2
	f[2] <<= 3
	f[3] <<= 5
	f[4] <<= 6
	f[6] <<= 1
	f[7] <<= 3
	f[8] <<= 4
	f[9] <<= 6

	F := func(i, s int) {
		out[s+0] |= byte(f[i] & 0xff)
		out[s+1] = byte((f[i] >> 8) & 0xff)
		out[s+2] = byte((f[i] >> 16) & 0xff)
		out[s+3] = byte((f[i] >> 24) & 0xff)
	}

	out[0] = 0
	out[16] = 0
	F(0, 0)
	F(1, 3)
	F(2, 6)
	F(3, 9)
	F(4, 12)
	F(5, 16)
	F(6, 19)
	F(7, 22)
	F(8, 25)
	F(9, 28)
}

func SwapConditional(a, b *Bignum25519, iswap uint64) {
	swap := uint32(-int32(iswap))

	x0 := swap & (a[0] ^ b[0])
	a[0] ^= x0
	b[0] ^= x0

	x1 := swap & (a[1] ^ b[1])
	a[1] ^= x1
	b[1] ^= x1

	x2 := swap & (a[2] ^ b[2])
	a[2] ^= x2
	b[2] ^= x2

	x3 := swap & (a[3] ^ b[3])
	a[3] ^= x3
	b[3] ^= x3

	x4 := swap & (a[4] ^ b[4])
	a[4] ^= x4
	b[4] ^= x4

	x5 := swap & (a[5] ^ b[5])
	a[5] ^= x5
	b[5] ^= x5

	x6 := swap & (a[6] ^ b[6])
	a[6] ^= x6
	b[6] ^= x6

	x7 := swap & (a[7] ^ b[7])
	a[7] ^= x7
	b[7] ^= x7

	x8 := swap & (a[8] ^ b[8])
	a[8] ^= x8
	b[8] ^= x8

	x9 := swap & (a[9] ^ b[9])
	a[9] ^= x9
	b[9] ^= x9
}

var (
	maxBignum = Bignum25519{
		0x3ffffff, 0x2000300, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff, 0x3ffffff, 0x1ffffff,
	}

	maxBignum2SquaredRaw = [32]byte{
		0x10, 0x05, 0x00, 0x40, 0xc2, 0x06, 0x40, 0x80, 0x41, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	maxBignum3SquaredRaw = [32]byte{
		0x64, 0x0b, 0x00, 0x10, 0x35, 0x0f, 0x90, 0x60, 0x13, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	maxBignumRaw = [32]byte{
		0x12, 0x00, 0x00, 0x04, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	maxBignumSquaredRaw = [32]byte{
		0x44, 0x01, 0x00, 0x90, 0xb0, 0x01, 0x10, 0x60, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
)

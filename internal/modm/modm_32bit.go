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

package modm

import "encoding/binary"

const (
	BitsPerLimb = 30
	LimbSize    = 9

	m0 uint32 = 0x1cf5d3ed
	m1 uint32 = 0x20498c69
	m2 uint32 = 0x2f79cd65
	m3 uint32 = 0x37be77a8
	m4 uint32 = 0x00000014
	m5 uint32 = 0x00000000
	m6 uint32 = 0x00000000
	m7 uint32 = 0x00000000
	m8 uint32 = 0x00001000

	mu0 uint32 = 0x0a2c131b
	mu1 uint32 = 0x3673968c
	mu2 uint32 = 0x06329a7e
	mu3 uint32 = 0x01885742
	mu4 uint32 = 0x3fffeb21
	mu5 uint32 = 0x3fffffff
	mu6 uint32 = 0x3fffffff
	mu7 uint32 = 0x3fffffff
	mu8 uint32 = 0x000fffff
)

type Element uint32
type Bignum256 [9]Element

func ltModM(a, b Element) Element {
	return (a - b) >> 31
}

func reduce(r *Bignum256) {
	var t Bignum256

	// t = r - m

	// pb = 0

	pb := Element(m0)
	b := ltModM(r[0], pb)
	t[0] = (r[0] - pb + (b << 30))
	pb = b

	pb += Element(m1)
	b = ltModM(r[1], pb)
	t[1] = (r[1] - pb + (b << 30))
	pb = b

	pb += Element(m2)
	b = ltModM(r[2], pb)
	t[2] = (r[2] - pb + (b << 30))
	pb = b

	pb += Element(m3)
	b = ltModM(r[3], pb)
	t[3] = (r[3] - pb + (b << 30))
	pb = b

	pb += Element(m4)
	b = ltModM(r[4], pb)
	t[4] = (r[4] - pb + (b << 30))
	pb = b

	pb += Element(m5)
	b = ltModM(r[5], pb)
	t[5] = (r[5] - pb + (b << 30))
	pb = b

	pb += Element(m6)
	b = ltModM(r[6], pb)
	t[6] = (r[6] - pb + (b << 30))
	pb = b

	pb += Element(m7)
	b = ltModM(r[7], pb)
	t[7] = (r[7] - pb + (b << 30))
	pb = b

	pb += Element(m8)
	b = ltModM(r[8], pb)
	t[8] = (r[8] - pb + (b << 16))

	// keep r if r was smaller than m
	mask := b - 1
	r[0] ^= mask & (r[0] ^ t[0])
	r[1] ^= mask & (r[1] ^ t[1])
	r[2] ^= mask & (r[2] ^ t[2])
	r[3] ^= mask & (r[3] ^ t[3])
	r[4] ^= mask & (r[4] ^ t[4])
	r[5] ^= mask & (r[5] ^ t[5])
	r[6] ^= mask & (r[6] ^ t[6])
	r[7] ^= mask & (r[7] ^ t[7])
	r[8] ^= mask & (r[8] ^ t[8])
}

func barrettReduce(r, q1, r1 *Bignum256) {
	var (
		q3, r2 Bignum256
		c      uint64
		f      Element
	)
	// q1 = x >> 248 = 264 bits = 9 30 bit elements
	// q2 = mu * q1
	// q3 = (q2 / 256(32+1)) = q2 / (2^8)^(32+1) = q2 >> 264
	c = uint64(mu0)*uint64(q1[7]) + uint64(mu1)*uint64(q1[6]) + uint64(mu2)*uint64(q1[5]) + uint64(mu3)*uint64(q1[4]) + uint64(mu4)*uint64(q1[3]) + uint64(mu5)*uint64(q1[2]) + uint64(mu6)*uint64(q1[1]) + uint64(mu7)*uint64(q1[0])

	c >>= 30

	c += uint64(mu0)*uint64(q1[8]) + uint64(mu1)*uint64(q1[7]) + uint64(mu2)*uint64(q1[6]) + uint64(mu3)*uint64(q1[5]) + uint64(mu4)*uint64(q1[4]) + uint64(mu5)*uint64(q1[3]) + uint64(mu6)*uint64(q1[2]) + uint64(mu7)*uint64(q1[1]) + uint64(mu8)*uint64(q1[0])

	f = Element(c)
	q3[0] = (f >> 24) & 0x3f
	c >>= 30

	c += uint64(mu1)*uint64(q1[8]) + uint64(mu2)*uint64(q1[7]) + uint64(mu3)*uint64(q1[6]) + uint64(mu4)*uint64(q1[5]) + uint64(mu5)*uint64(q1[4]) + uint64(mu6)*uint64(q1[3]) + uint64(mu7)*uint64(q1[2]) + uint64(mu8)*uint64(q1[1])

	f = Element(c)
	q3[0] |= (f << 6) & 0x3fffffff
	q3[1] = (f >> 24) & 0x3f
	c >>= 30

	c += uint64(mu2)*uint64(q1[8]) + uint64(mu3)*uint64(q1[7]) + uint64(mu4)*uint64(q1[6]) + uint64(mu5)*uint64(q1[5]) + uint64(mu6)*uint64(q1[4]) + uint64(mu7)*uint64(q1[3]) + uint64(mu8)*uint64(q1[2])

	f = Element(c)
	q3[1] |= (f << 6) & 0x3fffffff
	q3[2] = (f >> 24) & 0x3f
	c >>= 30

	c += uint64(mu3)*uint64(q1[8]) + uint64(mu4)*uint64(q1[7]) + uint64(mu5)*uint64(q1[6]) + uint64(mu6)*uint64(q1[5]) + uint64(mu7)*uint64(q1[4]) + uint64(mu8)*uint64(q1[3])

	f = Element(c)
	q3[2] |= (f << 6) & 0x3fffffff
	q3[3] = (f >> 24) & 0x3f
	c >>= 30

	c += uint64(mu4)*uint64(q1[8]) + uint64(mu5)*uint64(q1[7]) + uint64(mu6)*uint64(q1[6]) + uint64(mu7)*uint64(q1[5]) + uint64(mu8)*uint64(q1[4])

	f = Element(c)
	q3[3] |= (f << 6) & 0x3fffffff
	q3[4] = (f >> 24) & 0x3f
	c >>= 30

	c += uint64(mu5)*uint64(q1[8]) + uint64(mu6)*uint64(q1[7]) + uint64(mu7)*uint64(q1[6]) + uint64(mu8)*uint64(q1[5])

	f = Element(c)
	q3[4] |= (f << 6) & 0x3fffffff
	q3[5] = (f >> 24) & 0x3f
	c >>= 30

	c += uint64(mu6)*uint64(q1[8]) + uint64(mu7)*uint64(q1[7]) + uint64(mu8)*uint64(q1[6])

	f = Element(c)
	q3[5] |= (f << 6) & 0x3fffffff
	q3[6] = (f >> 24) & 0x3f
	c >>= 30

	c += uint64(mu7)*uint64(q1[8]) + uint64(mu8)*uint64(q1[7])

	f = Element(c)
	q3[6] |= (f << 6) & 0x3fffffff
	q3[7] = (f >> 24) & 0x3f
	c >>= 30

	c += uint64(mu8) * uint64(q1[8])

	f = Element(c)
	q3[7] |= (f << 6) & 0x3fffffff
	q3[8] = Element(c >> 24)

	// r1 = (x mod 256^(32+1)) = x mod (2^8)(31+1) = x & ((1 << 264) - 1)
	// r2 = (q3 * m) mod (256^(32+1)) = (q3 * m) & ((1 << 264) - 1)
	c = uint64(m0) * uint64(q3[0])

	r2[0] = Element(c & 0x3fffffff)
	c >>= 30

	c += uint64(m0)*uint64(q3[1]) + uint64(m1)*uint64(q3[0])

	r2[1] = Element(c & 0x3fffffff)
	c >>= 30

	c += uint64(m0)*uint64(q3[2]) + uint64(m1)*uint64(q3[1]) + uint64(m2)*uint64(q3[0])

	r2[2] = Element(c & 0x3fffffff)
	c >>= 30

	c += uint64(m0)*uint64(q3[3]) + uint64(m1)*uint64(q3[2]) + uint64(m2)*uint64(q3[1]) + uint64(m3)*uint64(q3[0])

	r2[3] = Element(c & 0x3fffffff)
	c >>= 30

	c += uint64(m0)*uint64(q3[4]) + uint64(m1)*uint64(q3[3]) + uint64(m2)*uint64(q3[2]) + uint64(m3)*uint64(q3[1]) + uint64(m4)*uint64(q3[0])

	r2[4] = Element(c & 0x3fffffff)
	c >>= 30

	c += uint64(m0)*uint64(q3[5]) + uint64(m1)*uint64(q3[4]) + uint64(m2)*uint64(q3[3]) + uint64(m3)*uint64(q3[2]) + uint64(m4)*uint64(q3[1]) + uint64(m5)*uint64(q3[0])

	r2[5] = Element(c & 0x3fffffff)
	c >>= 30

	c += uint64(m0)*uint64(q3[6]) + uint64(m1)*uint64(q3[5]) + uint64(m2)*uint64(q3[4]) + uint64(m3)*uint64(q3[3]) + uint64(m4)*uint64(q3[2]) + uint64(m5)*uint64(q3[1]) + uint64(m6)*uint64(q3[0])

	r2[6] = Element(c & 0x3fffffff)
	c >>= 30

	c += uint64(m0)*uint64(q3[7]) + uint64(m1)*uint64(q3[6]) + uint64(m2)*uint64(q3[5]) + uint64(m3)*uint64(q3[4]) + uint64(m4)*uint64(q3[3]) + uint64(m5)*uint64(q3[2]) + uint64(m6)*uint64(q3[1]) + uint64(m7)*uint64(q3[0])

	r2[7] = Element(c & 0x3fffffff)
	c >>= 30

	c += uint64(m0)*uint64(q3[8]) + uint64(m1)*uint64(q3[7]) + uint64(m2)*uint64(q3[6]) + uint64(m3)*uint64(q3[5]) + uint64(m4)*uint64(q3[4]) + uint64(m5)*uint64(q3[3]) + uint64(m6)*uint64(q3[2]) + uint64(m7)*uint64(q3[1]) + uint64(m8)*uint64(q3[0])

	r2[8] = Element(c & 0xffffff)

	// r = r1 - r2
	// if (r < 0) r += (1 << 264)
	pb := r2[0]
	b := ltModM(r1[0], pb)
	r[0] = (r1[0] - pb + (b << 30))
	pb = b

	pb += r2[1]
	b = ltModM(r1[1], pb)
	r[1] = (r1[1] - pb + (b << 30))
	pb = b

	pb += r2[2]
	b = ltModM(r1[2], pb)
	r[2] = (r1[2] - pb + (b << 30))
	pb = b

	pb += r2[3]
	b = ltModM(r1[3], pb)
	r[3] = (r1[3] - pb + (b << 30))
	pb = b

	pb += r2[4]
	b = ltModM(r1[4], pb)
	r[4] = (r1[4] - pb + (b << 30))
	pb = b

	pb += r2[5]
	b = ltModM(r1[5], pb)
	r[5] = (r1[5] - pb + (b << 30))
	pb = b

	pb += r2[6]
	b = ltModM(r1[6], pb)
	r[6] = (r1[6] - pb + (b << 30))
	pb = b

	pb += r2[7]
	b = ltModM(r1[7], pb)
	r[7] = (r1[7] - pb + (b << 30))
	pb = b

	pb += r2[8]
	b = ltModM(r1[8], pb)
	r[8] = (r1[8] - pb + (b << 24))

	reduce(r)
	reduce(r)
}

func (r *Bignum256) Reset() {
	for i := range r {
		r[i] = 0
	}
}

func Add(r, x, y *Bignum256) {
	c := x[0] + y[0]
	r[0] = c & 0x3fffffff
	c >>= 30

	c += x[1] + y[1]
	r[1] = c & 0x3fffffff
	c >>= 30

	c += x[2] + y[2]
	r[2] = c & 0x3fffffff
	c >>= 30

	c += x[3] + y[3]
	r[3] = c & 0x3fffffff
	c >>= 30

	c += x[4] + y[4]
	r[4] = c & 0x3fffffff
	c >>= 30

	c += x[5] + y[5]
	r[5] = c & 0x3fffffff
	c >>= 30

	c += x[6] + y[6]
	r[6] = c & 0x3fffffff
	c >>= 30

	c += x[7] + y[7]
	r[7] = c & 0x3fffffff
	c >>= 30

	c += x[8] + y[8]
	r[8] = c

	reduce(r)
}

func Mul(r, x, y *Bignum256) {
	var (
		q1, r1 Bignum256
		c      uint64
		f      Element
	)

	// r1 = (x mod 256^(32+1)) = x mod (2^8)(31+1) = x & ((1 << 264) - 1)
	// q1 = x >> 248 = 264 bits = 9 30 bit elements
	c = uint64(x[0]) * uint64(y[0])

	f = Element(c)
	r1[0] = (f & 0x3fffffff)
	c >>= 30

	c += uint64(x[0])*uint64(y[1]) + uint64(x[1])*uint64(y[0])

	f = Element(c)
	r1[1] = (f & 0x3fffffff)
	c >>= 30

	c += uint64(x[0])*uint64(y[2]) + uint64(x[1])*uint64(y[1]) + uint64(x[2])*uint64(y[0])

	f = Element(c)
	r1[2] = (f & 0x3fffffff)
	c >>= 30

	c += uint64(x[0])*uint64(y[3]) + uint64(x[1])*uint64(y[2]) + uint64(x[2])*uint64(y[1]) + uint64(x[3])*uint64(y[0])

	f = Element(c)
	r1[3] = (f & 0x3fffffff)
	c >>= 30

	c += uint64(x[0])*uint64(y[4]) + uint64(x[1])*uint64(y[3]) + uint64(x[2])*uint64(y[2]) + uint64(x[3])*uint64(y[1]) + uint64(x[4])*uint64(y[0])

	f = Element(c)
	r1[4] = (f & 0x3fffffff)
	c >>= 30

	c += uint64(x[0])*uint64(y[5]) + uint64(x[1])*uint64(y[4]) + uint64(x[2])*uint64(y[3]) + uint64(x[3])*uint64(y[2]) + uint64(x[4])*uint64(y[1]) + uint64(x[5])*uint64(y[0])

	f = Element(c)
	r1[5] = (f & 0x3fffffff)
	c >>= 30

	c += uint64(x[0])*uint64(y[6]) + uint64(x[1])*uint64(y[5]) + uint64(x[2])*uint64(y[4]) + uint64(x[3])*uint64(y[3]) + uint64(x[4])*uint64(y[2]) + uint64(x[5])*uint64(y[1]) + uint64(x[6])*uint64(y[0])

	f = Element(c)
	r1[6] = (f & 0x3fffffff)
	c >>= 30

	c += uint64(x[0])*uint64(y[7]) + uint64(x[1])*uint64(y[6]) + uint64(x[2])*uint64(y[5]) + uint64(x[3])*uint64(y[4]) + uint64(x[4])*uint64(y[3]) + uint64(x[5])*uint64(y[2]) + uint64(x[6])*uint64(y[1]) + uint64(x[7])*uint64(y[0])

	f = Element(c)
	r1[7] = (f & 0x3fffffff)
	c >>= 30

	c += uint64(x[0])*uint64(y[8]) + uint64(x[1])*uint64(y[7]) + uint64(x[2])*uint64(y[6]) + uint64(x[3])*uint64(y[5]) + uint64(x[4])*uint64(y[4]) + uint64(x[5])*uint64(y[3]) + uint64(x[6])*uint64(y[2]) + uint64(x[7])*uint64(y[1]) + uint64(x[8])*uint64(y[0])

	f = Element(c)
	r1[8] = (f & 0x00ffffff)
	q1[0] = (f >> 8) & 0x3fffff
	c >>= 30

	c += uint64(x[1])*uint64(y[8]) + uint64(x[2])*uint64(y[7]) + uint64(x[3])*uint64(y[6]) + uint64(x[4])*uint64(y[5]) + uint64(x[5])*uint64(y[4]) + uint64(x[6])*uint64(y[3]) + uint64(x[7])*uint64(y[2]) + uint64(x[8])*uint64(y[1])

	f = Element(c)
	q1[0] = (q1[0] | (f << 22)) & 0x3fffffff
	q1[1] = (f >> 8) & 0x3fffff
	c >>= 30

	c += uint64(x[2])*uint64(y[8]) + uint64(x[3])*uint64(y[7]) + uint64(x[4])*uint64(y[6]) + uint64(x[5])*uint64(y[5]) + uint64(x[6])*uint64(y[4]) + uint64(x[7])*uint64(y[3]) + uint64(x[8])*uint64(y[2])

	f = Element(c)
	q1[1] = (q1[1] | (f << 22)) & 0x3fffffff
	q1[2] = (f >> 8) & 0x3fffff
	c >>= 30

	c += uint64(x[3])*uint64(y[8]) + uint64(x[4])*uint64(y[7]) + uint64(x[5])*uint64(y[6]) + uint64(x[6])*uint64(y[5]) + uint64(x[7])*uint64(y[4]) + uint64(x[8])*uint64(y[3])

	f = Element(c)
	q1[2] = (q1[2] | (f << 22)) & 0x3fffffff
	q1[3] = (f >> 8) & 0x3fffff
	c >>= 30

	c += uint64(x[4])*uint64(y[8]) + uint64(x[5])*uint64(y[7]) + uint64(x[6])*uint64(y[6]) + uint64(x[7])*uint64(y[5]) + uint64(x[8])*uint64(y[4])

	f = Element(c)
	q1[3] = (q1[3] | (f << 22)) & 0x3fffffff
	q1[4] = (f >> 8) & 0x3fffff
	c >>= 30

	c += uint64(x[5])*uint64(y[8]) + uint64(x[6])*uint64(y[7]) + uint64(x[7])*uint64(y[6]) + uint64(x[8])*uint64(y[5])

	f = Element(c)
	q1[4] = (q1[4] | (f << 22)) & 0x3fffffff
	q1[5] = (f >> 8) & 0x3fffff
	c >>= 30

	c += uint64(x[6])*uint64(y[8]) + uint64(x[7])*uint64(y[7]) + uint64(x[8])*uint64(y[6])

	f = Element(c)
	q1[5] = (q1[5] | (f << 22)) & 0x3fffffff
	q1[6] = (f >> 8) & 0x3fffff
	c >>= 30

	c += uint64(x[7])*uint64(y[8]) + uint64(x[8])*uint64(y[7])

	f = Element(c)
	q1[6] = (q1[6] | (f << 22)) & 0x3fffffff
	q1[7] = (f >> 8) & 0x3fffff
	c >>= 30

	c += uint64(x[8]) * uint64(y[8])

	f = Element(c)
	q1[7] = (q1[7] | (f << 22)) & 0x3fffffff
	q1[8] = (f >> 8) & 0x3fffff

	barrettReduce(r, &q1, &r1)
}

func Expand(out *Bignum256, in []byte) {
	var (
		work [64]byte
		x    [16]Element
	)

	copy(work[:], in)
	x[0] = Element(binary.LittleEndian.Uint32(work[0:]))
	x[1] = Element(binary.LittleEndian.Uint32(work[4:]))
	x[2] = Element(binary.LittleEndian.Uint32(work[8:]))
	x[3] = Element(binary.LittleEndian.Uint32(work[12:]))
	x[4] = Element(binary.LittleEndian.Uint32(work[16:]))
	x[5] = Element(binary.LittleEndian.Uint32(work[20:]))
	x[6] = Element(binary.LittleEndian.Uint32(work[24:]))
	x[7] = Element(binary.LittleEndian.Uint32(work[28:]))
	x[8] = Element(binary.LittleEndian.Uint32(work[32:]))
	x[9] = Element(binary.LittleEndian.Uint32(work[36:]))
	x[10] = Element(binary.LittleEndian.Uint32(work[40:]))
	x[11] = Element(binary.LittleEndian.Uint32(work[44:]))
	x[12] = Element(binary.LittleEndian.Uint32(work[48:]))
	x[13] = Element(binary.LittleEndian.Uint32(work[52:]))
	x[14] = Element(binary.LittleEndian.Uint32(work[56:]))
	x[15] = Element(binary.LittleEndian.Uint32(work[60:]))

	// r1 = (x mod 256^(32+1)) = x mod (2^8)(31+1) = x & ((1 << 264) - 1)
	out[0] = (x[0]) & 0x3fffffff
	out[1] = ((x[0] >> 30) | (x[1] << 2)) & 0x3fffffff
	out[2] = ((x[1] >> 28) | (x[2] << 4)) & 0x3fffffff
	out[3] = ((x[2] >> 26) | (x[3] << 6)) & 0x3fffffff
	out[4] = ((x[3] >> 24) | (x[4] << 8)) & 0x3fffffff
	out[5] = ((x[4] >> 22) | (x[5] << 10)) & 0x3fffffff
	out[6] = ((x[5] >> 20) | (x[6] << 12)) & 0x3fffffff
	out[7] = ((x[6] >> 18) | (x[7] << 14)) & 0x3fffffff
	out[8] = ((x[7] >> 16) | (x[8] << 16)) & 0x00ffffff

	// 8*31 = 248 bits, no need to reduce
	if len(in) < 32 {
		return
	}

	// q1 = x >> 248 = 264 bits = 9 30 bit elements
	var q1 Bignum256
	q1[0] = ((x[7] >> 24) | (x[8] << 8)) & 0x3fffffff
	q1[1] = ((x[8] >> 22) | (x[9] << 10)) & 0x3fffffff
	q1[2] = ((x[9] >> 20) | (x[10] << 12)) & 0x3fffffff
	q1[3] = ((x[10] >> 18) | (x[11] << 14)) & 0x3fffffff
	q1[4] = ((x[11] >> 16) | (x[12] << 16)) & 0x3fffffff
	q1[5] = ((x[12] >> 14) | (x[13] << 18)) & 0x3fffffff
	q1[6] = ((x[13] >> 12) | (x[14] << 20)) & 0x3fffffff
	q1[7] = ((x[14] >> 10) | (x[15] << 22)) & 0x3fffffff
	q1[8] = (x[15] >> 8)

	barrettReduce(out, &q1, out)
}

func ExpandRaw(out *Bignum256, in []byte) {
	var x [8]Element

	_ = in[31]
	x[0] = Element(binary.LittleEndian.Uint32(in[0:]))
	x[1] = Element(binary.LittleEndian.Uint32(in[4:]))
	x[2] = Element(binary.LittleEndian.Uint32(in[8:]))
	x[3] = Element(binary.LittleEndian.Uint32(in[12:]))
	x[4] = Element(binary.LittleEndian.Uint32(in[16:]))
	x[5] = Element(binary.LittleEndian.Uint32(in[20:]))
	x[6] = Element(binary.LittleEndian.Uint32(in[24:]))
	x[7] = Element(binary.LittleEndian.Uint32(in[28:]))

	out[0] = (x[0]) & 0x3fffffff
	out[1] = ((x[0] >> 30) | (x[1] << 2)) & 0x3fffffff
	out[2] = ((x[1] >> 28) | (x[2] << 4)) & 0x3fffffff
	out[3] = ((x[2] >> 26) | (x[3] << 6)) & 0x3fffffff
	out[4] = ((x[3] >> 24) | (x[4] << 8)) & 0x3fffffff
	out[5] = ((x[4] >> 22) | (x[5] << 10)) & 0x3fffffff
	out[6] = ((x[5] >> 20) | (x[6] << 12)) & 0x3fffffff
	out[7] = ((x[6] >> 18) | (x[7] << 14)) & 0x3fffffff
	out[8] = (x[7] >> 16) & 0x0000ffff
}

func Contract(out []byte, in *Bignum256) {
	_ = out[31]
	binary.LittleEndian.PutUint32(out[0:4], uint32((in[0])|(in[1]<<30)))
	binary.LittleEndian.PutUint32(out[4:8], uint32((in[1]>>2)|(in[2]<<28)))
	binary.LittleEndian.PutUint32(out[8:12], uint32((in[2]>>4)|(in[3]<<26)))
	binary.LittleEndian.PutUint32(out[12:16], uint32((in[3]>>6)|(in[4]<<24)))
	binary.LittleEndian.PutUint32(out[16:20], uint32((in[4]>>8)|(in[5]<<22)))
	binary.LittleEndian.PutUint32(out[20:24], uint32((in[5]>>10)|(in[6]<<20)))
	binary.LittleEndian.PutUint32(out[24:28], uint32((in[6]>>12)|(in[7]<<18)))
	binary.LittleEndian.PutUint32(out[28:32], uint32((in[7]>>14)|(in[8]<<16)))
}

func ContractWindow4(r *[64]int8, in *Bignum256) {
	var (
		quads int
		v     Element
	)
	for i := 0; i < 8; i += 2 {
		v = in[i]
		for j := 0; j < 7; j++ {
			r[quads] = int8(v & 15)
			quads++
			v >>= 4
		}
		v |= in[i+1] << 2
		for j := 0; j < 8; j++ {
			r[quads] = int8(v & 15)
			quads++
			v >>= 4
		}
	}
	v = in[8]
	r[quads+0] = int8(v & 15)
	v >>= 4
	r[quads+1] = int8(v & 15)
	v >>= 4
	r[quads+2] = int8(v & 15)
	v >>= 4
	r[quads+3] = int8(v & 15)
	v >>= 4

	// making it signed
	var carry int8
	for i := 0; i < 63; i++ {
		r[i] += carry
		r[i+1] += (r[i] >> 4)
		r[i] &= 15
		carry = (r[i] >> 3)
		r[i] -= (carry << 4)
	}
	r[63] += carry
}

func ContractSlidingWindow(r *[256]int8, s *Bignum256, windowSize uint) {
	const soplen = 256
	var (
		v    Element
		bits int
	)

	// first put the binary expansion into r
	for i := 0; i < 8; i++ {
		v = s[i]
		for j := 0; j < 30; j++ {
			r[bits] = int8(v & 1)
			bits++
			v >>= 1
		}
	}
	v = s[8]
	for j := 0; j < 16; j++ {
		r[bits] = int8(v & 1)
		bits++
		v >>= 1
	}

	// Making it sliding window
	m := int8((1 << (windowSize - 1)) - 1)
	for j := 0; j < soplen; j++ {
		if r[j] == 0 {
			continue
		}

		for b := 1; (b < (soplen - j)) && (b <= 6); b++ {
			shift := uint(b)
			if (r[j] + (r[j+b] << shift)) <= m {
				r[j] += r[j+b] << shift
				r[j+b] = 0
			} else if (r[j] - (r[j+b] << shift)) >= -m {
				r[j] -= r[j+b] << shift
				for k := j + b; k < soplen; k++ {
					if r[k] == 0 {
						r[k] = 1
						break
					}
					r[k] = 0
				}
			} else if r[j+b] != 0 {
				break
			}
		}
	}
}

func SubVartime(out, a, b *Bignum256, limbSize int) {
	var (
		carry Element
		i     int
	)

	switch limbSize {
	case 8:
		out[i] = (a[i] - b[i]) - carry
		carry = (out[i] >> 31)
		out[i] &= 0x3fffffff
		i++
		fallthrough
	case 7:
		out[i] = (a[i] - b[i]) - carry
		carry = (out[i] >> 31)
		out[i] &= 0x3fffffff
		i++
		fallthrough
	case 6:
		out[i] = (a[i] - b[i]) - carry
		carry = (out[i] >> 31)
		out[i] &= 0x3fffffff
		i++
		fallthrough
	case 5:
		out[i] = (a[i] - b[i]) - carry
		carry = (out[i] >> 31)
		out[i] &= 0x3fffffff
		i++
		fallthrough
	case 4:
		out[i] = (a[i] - b[i]) - carry
		carry = (out[i] >> 31)
		out[i] &= 0x3fffffff
		i++
		fallthrough
	case 3:
		out[i] = (a[i] - b[i]) - carry
		carry = (out[i] >> 31)
		out[i] &= 0x3fffffff
		i++
		fallthrough
	case 2:
		out[i] = (a[i] - b[i]) - carry
		carry = (out[i] >> 31)
		out[i] &= 0x3fffffff
		i++
		fallthrough
	case 1:
		out[i] = (a[i] - b[i]) - carry
		carry = (out[i] >> 31)
		out[i] &= 0x3fffffff
		i++
		fallthrough
	default:
		out[i] = (a[i] - b[i]) - carry
	}
}

func LessThanVartime(a, b *Bignum256, limbSize int) bool {
	switch limbSize {
	case 8:
		if a[8] > b[8] {
			return false
		}
		if a[8] < b[8] {
			return true
		}
		fallthrough
	case 7:
		if a[7] > b[7] {
			return false
		}
		if a[7] < b[7] {
			return true
		}
		fallthrough
	case 6:
		if a[6] > b[6] {
			return false
		}
		if a[6] < b[6] {
			return true
		}
		fallthrough
	case 5:
		if a[5] > b[5] {
			return false
		}
		if a[5] < b[5] {
			return true
		}
		fallthrough
	case 4:
		if a[4] > b[4] {
			return false
		}
		if a[4] < b[4] {
			return true
		}
		fallthrough
	case 3:
		if a[3] > b[3] {
			return false
		}
		if a[3] < b[3] {
			return true
		}
		fallthrough
	case 2:
		if a[2] > b[2] {
			return false
		}
		if a[2] < b[2] {
			return true
		}
		fallthrough
	case 1:
		if a[1] > b[1] {
			return false
		}
		if a[1] < b[1] {
			return true
		}
		fallthrough
	case 0:
		if a[0] > b[0] {
			return false
		}
		if a[0] < b[0] {
			return true
		}
	}
	return false
}

func LessThanOrEqualVartime(a, b *Bignum256, limbSize int) bool {
	switch limbSize {
	case 8:
		if a[8] > b[8] {
			return false
		}
		if a[8] < b[8] {
			return true
		}
		fallthrough
	case 7:
		if a[7] > b[7] {
			return false
		}
		if a[7] < b[7] {
			return true
		}
		fallthrough
	case 6:
		if a[6] > b[6] {
			return false
		}
		if a[6] < b[6] {
			return true
		}
		fallthrough
	case 5:
		if a[5] > b[5] {
			return false
		}
		if a[5] < b[5] {
			return true
		}
		fallthrough
	case 4:
		if a[4] > b[4] {
			return false
		}
		if a[4] < b[4] {
			return true
		}
		fallthrough
	case 3:
		if a[3] > b[3] {
			return false
		}
		if a[3] < b[3] {
			return true
		}
		fallthrough
	case 2:
		if a[2] > b[2] {
			return false
		}
		if a[2] < b[2] {
			return true
		}
		fallthrough
	case 1:
		if a[1] > b[1] {
			return false
		}
		if a[1] < b[1] {
			return true
		}
		fallthrough
	case 0:
		if a[0] > b[0] {
			return false
		}
		if a[0] < b[0] {
			return true
		}
	}
	return true
}

func IsZeroVartime(a *Bignum256) bool {
	for _, v := range a {
		if v != 0 {
			return false
		}
	}
	return true
}

func IsOneVartime(a *Bignum256) bool {
	for i, v := range a {
		var cmp Element
		if i == 0 {
			cmp = 1
		}
		if v != cmp {
			return false
		}
	}
	return true
}

func IsAtMost128bitsVartime(a *Bignum256) bool {
	mask := a[8] | a[7] | a[6] | a[5] | (a[4] & 0x3fffff00)

	return mask == 0
}

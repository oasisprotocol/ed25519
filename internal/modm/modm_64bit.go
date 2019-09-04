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

// +build amd64 go1.13,arm64 go1.13,ppc64le go1.13,ppc64

package modm

import (
	"encoding/binary"

	"github.com/oasislabs/ed25519/internal/uint128"
)

const (
	BitsPerLimb = 56
	LimbSize    = 5

	// modm_m
	m0 uint64 = 0x12631a5cf5d3ed
	m1 uint64 = 0xf9dea2f79cd658
	m2 uint64 = 0x000000000014de
	m3 uint64 = 0x00000000000000
	m4 uint64 = 0x00000010000000

	// modm_mu
	mu0 uint64 = 0x9ce5a30a2c131b
	mu1 uint64 = 0x215d086329a7ed
	mu2 uint64 = 0xffffffffeb2106
	mu3 uint64 = 0xffffffffffffff
	mu4 uint64 = 0x00000fffffffff
)

type Element uint64
type Bignum256 [5]Element

func ltModM(a, b Element) Element {
	// bignum256modm_element_t lt_modm(bignum256modm_element_t a, bignum256modm_element_t b)
	return (a - b) >> 63
}

func reduce(r *Bignum256) {
	// reduce256_modm(bignum256modm r)
	var t Bignum256

	// t = r - m

	// pb = 0

	pb := Element(m0)
	b := ltModM(r[0], pb)
	t[0] = (r[0] - pb + (b << 56))
	pb = b

	pb += Element(m1)
	b = ltModM(r[1], pb)
	t[1] = (r[1] - pb + (b << 56))
	pb = b

	pb += Element(m2)
	b = ltModM(r[2], pb)
	t[2] = (r[2] - pb + (b << 56))
	pb = b

	pb += Element(m3)
	b = ltModM(r[3], pb)
	t[3] = (r[3] - pb + (b << 56))
	pb = b

	pb += Element(m4)
	b = ltModM(r[4], pb)
	t[4] = (r[4] - pb + (b << 32))

	// keep r if r was smaller than m
	mask := b - 1

	r[0] ^= mask & (r[0] ^ t[0])

	r[1] ^= mask & (r[1] ^ t[1])

	r[2] ^= mask & (r[2] ^ t[2])

	r[3] ^= mask & (r[3] ^ t[3])

	r[4] ^= mask & (r[4] ^ t[4])
}

func barrettReduce(r, q1, r1 *Bignum256) {
	// barrett_reduce256_modm(bignum256modm r, const bignum256modm q1, const bignum256modm r1)
	var (
		q3, r2 Bignum256
		c, mul uint128.Uint128
	)

	// q1 = x >> 248 = 264 bits = 5 56 bit elements
	// q2 = mu * q1
	// q3 = (q2 / 256(32+1)) = q2 / (2^8)^(32+1) = q2 >> 264
	uint128.Mul64x64(&c, mu0, uint64(q1[3]))
	uint128.Mul64x64(&mul, mu3, uint64(q1[0]))
	uint128.Add(&c, &mul)
	uint128.Mul64x64(&mul, mu1, uint64(q1[2]))
	uint128.Add(&c, &mul)
	uint128.Mul64x64(&mul, mu2, uint64(q1[1]))
	uint128.Add(&c, &mul)
	f := uint128.Shr(&c, 56)

	uint128.Mul64x64(&c, mu0, uint64(q1[4]))
	uint128.Add64(&c, f)
	uint128.Mul64x64(&mul, mu4, uint64(q1[0]))
	uint128.Add(&c, &mul)
	uint128.Mul64x64(&mul, mu3, uint64(q1[1]))
	uint128.Add(&c, &mul)
	uint128.Mul64x64(&mul, mu1, uint64(q1[3]))
	uint128.Add(&c, &mul)
	uint128.Mul64x64(&mul, mu2, uint64(q1[2]))
	uint128.Add(&c, &mul)

	f = uint128.Lo(&c)
	q3[0] = Element((f >> 40) & 0xffff)
	f = uint128.Shr(&c, 56)

	uint128.Mul64x64(&c, mu4, uint64(q1[1]))
	uint128.Add64(&c, f)
	uint128.Mul64x64(&mul, mu1, uint64(q1[4]))
	uint128.Add(&c, &mul)
	uint128.Mul64x64(&mul, mu2, uint64(q1[3]))
	uint128.Add(&c, &mul)
	uint128.Mul64x64(&mul, mu3, uint64(q1[2]))
	uint128.Add(&c, &mul)

	f = uint128.Lo(&c)
	q3[0] |= Element((f << 16) & 0xffffffffffffff)
	q3[1] = Element((f >> 40) & 0xffff)
	f = uint128.Shr(&c, 56)

	uint128.Mul64x64(&c, mu4, uint64(q1[2]))
	uint128.Add64(&c, f)
	uint128.Mul64x64(&mul, mu2, uint64(q1[4]))
	uint128.Add(&c, &mul)
	uint128.Mul64x64(&mul, mu3, uint64(q1[3]))
	uint128.Add(&c, &mul)

	f = uint128.Lo(&c)
	q3[1] |= Element((f << 16) & 0xffffffffffffff)
	q3[2] = Element((f >> 40) & 0xffff)
	f = uint128.Shr(&c, 56)

	uint128.Mul64x64(&c, mu4, uint64(q1[3]))
	uint128.Add64(&c, f)
	uint128.Mul64x64(&mul, mu3, uint64(q1[4]))
	uint128.Add(&c, &mul)

	f = uint128.Lo(&c)
	q3[2] |= Element((f << 16) & 0xffffffffffffff)
	q3[3] = Element((f >> 40) & 0xffff)
	f = uint128.Shr(&c, 56)

	uint128.Mul64x64(&c, mu4, uint64(q1[4]))
	uint128.Add64(&c, f)

	f = uint128.Lo(&c)
	q3[3] |= Element((f << 16) & 0xffffffffffffff)
	q3[4] = Element((f >> 40) & 0xffff)
	f = uint128.Shr(&c, 56)

	q3[4] |= Element((f << 16))

	uint128.Mul64x64(&c, m0, uint64(q3[0]))

	r2[0] = Element(uint128.Lo(&c) & 0xffffffffffffff)
	f = uint128.Shr(&c, 56)

	uint128.Mul64x64(&c, m0, uint64(q3[1]))
	uint128.Add64(&c, f)
	uint128.Mul64x64(&mul, m1, uint64(q3[0]))
	uint128.Add(&c, &mul)

	r2[1] = Element(uint128.Lo(&c) & 0xffffffffffffff)
	f = uint128.Shr(&c, 56)

	uint128.Mul64x64(&c, m0, uint64(q3[2]))
	uint128.Add64(&c, f)
	uint128.Mul64x64(&mul, m2, uint64(q3[0]))
	uint128.Add(&c, &mul)
	uint128.Mul64x64(&mul, m1, uint64(q3[1]))
	uint128.Add(&c, &mul)

	r2[2] = Element(uint128.Lo(&c) & 0xffffffffffffff)
	f = uint128.Shr(&c, 56)

	uint128.Mul64x64(&c, m0, uint64(q3[3]))
	uint128.Add64(&c, f)
	uint128.Mul64x64(&mul, m3, uint64(q3[0]))
	uint128.Add(&c, &mul)
	uint128.Mul64x64(&mul, m1, uint64(q3[2]))
	uint128.Add(&c, &mul)
	uint128.Mul64x64(&mul, m2, uint64(q3[1]))
	uint128.Add(&c, &mul)

	r2[3] = Element(uint128.Lo(&c) & 0xffffffffffffff)
	f = uint128.Shr(&c, 56)

	uint128.Mul64x64(&c, m0, uint64(q3[4]))
	uint128.Add64(&c, f)
	uint128.Mul64x64(&mul, m4, uint64(q3[0]))
	uint128.Add(&c, &mul)
	uint128.Mul64x64(&mul, m3, uint64(q3[1]))
	uint128.Add(&c, &mul)
	uint128.Mul64x64(&mul, m1, uint64(q3[3]))
	uint128.Add(&c, &mul)
	uint128.Mul64x64(&mul, m2, uint64(q3[2]))
	uint128.Add(&c, &mul)

	r2[4] = Element(uint128.Lo(&c) & 0x0000ffffffffff)

	pb := r2[0]
	b := ltModM(r1[0], pb)
	r[0] = (r1[0] - pb + (b << 56))
	pb = b

	pb += r2[1]
	b = ltModM(r1[1], pb)
	r[1] = (r1[1] - pb + (b << 56))
	pb = b

	pb += r2[2]
	b = ltModM(r1[2], pb)
	r[2] = (r1[2] - pb + (b << 56))
	pb = b

	pb += r2[3]
	b = ltModM(r1[3], pb)
	r[3] = (r1[3] - pb + (b << 56))
	pb = b

	pb += r2[4]
	b = ltModM(r1[4], pb)
	r[4] = (r1[4] - pb + (b << 40))

	reduce(r)
	reduce(r)
}

func (r *Bignum256) Reset() {
	for i := range r {
		r[i] = 0
	}
}

func Add(r, x, y *Bignum256) {
	// add256_modm(bignum256modm r, const bignum256modm x, const bignum256modm y)
	c := x[0] + y[0]
	r[0] = c & 0xffffffffffffff
	c >>= 56

	c += x[1] + y[1]
	r[1] = c & 0xffffffffffffff
	c >>= 56

	c += x[2] + y[2]
	r[2] = c & 0xffffffffffffff
	c >>= 56

	c += x[3] + y[3]
	r[3] = c & 0xffffffffffffff
	c >>= 56

	c += x[4] + y[4]
	r[4] = c

	reduce(r)
}

func Mul(r, x, y *Bignum256) {
	// mul256_modm(bignum256modm r, const bignum256modm x, const bignum256modm y)
	var (
		q1, r1 Bignum256
		c, mul uint128.Uint128
	)

	uint128.Mul64x64(&c, uint64(x[0]), uint64(y[0]))

	f := uint128.Lo(&c)
	r1[0] = Element(f & 0xffffffffffffff)
	f = uint128.Shr(&c, 56)

	uint128.Mul64x64(&c, uint64(x[0]), uint64(y[1]))
	uint128.Add64(&c, f)
	uint128.Mul64x64(&mul, uint64(x[1]), uint64(y[0]))
	uint128.Add(&c, &mul)

	f = uint128.Lo(&c)
	r1[1] = Element(f & 0xffffffffffffff)
	f = uint128.Shr(&c, 56)

	uint128.Mul64x64(&c, uint64(x[0]), uint64(y[2]))
	uint128.Add64(&c, f)
	uint128.Mul64x64(&mul, uint64(x[2]), uint64(y[0]))
	uint128.Add(&c, &mul)
	uint128.Mul64x64(&mul, uint64(x[1]), uint64(y[1]))
	uint128.Add(&c, &mul)

	f = uint128.Lo(&c)
	r1[2] = Element(f & 0xffffffffffffff)
	f = uint128.Shr(&c, 56)

	uint128.Mul64x64(&c, uint64(x[0]), uint64(y[3]))
	uint128.Add64(&c, f)
	uint128.Mul64x64(&mul, uint64(x[3]), uint64(y[0]))
	uint128.Add(&c, &mul)
	uint128.Mul64x64(&mul, uint64(x[1]), uint64(y[2]))
	uint128.Add(&c, &mul)
	uint128.Mul64x64(&mul, uint64(x[2]), uint64(y[1]))
	uint128.Add(&c, &mul)

	f = uint128.Lo(&c)
	r1[3] = Element(f & 0xffffffffffffff)
	f = uint128.Shr(&c, 56)

	uint128.Mul64x64(&c, uint64(x[0]), uint64(y[4]))
	uint128.Add64(&c, f)
	uint128.Mul64x64(&mul, uint64(x[4]), uint64(y[0]))
	uint128.Add(&c, &mul)
	uint128.Mul64x64(&mul, uint64(x[3]), uint64(y[1]))
	uint128.Add(&c, &mul)
	uint128.Mul64x64(&mul, uint64(x[1]), uint64(y[3]))
	uint128.Add(&c, &mul)
	uint128.Mul64x64(&mul, uint64(x[2]), uint64(y[2]))
	uint128.Add(&c, &mul)

	f = uint128.Lo(&c)
	r1[4] = Element(f & 0x0000ffffffffff)
	q1[0] = Element((f >> 24) & 0xffffffff)
	f = uint128.Shr(&c, 56)

	uint128.Mul64x64(&c, uint64(x[4]), uint64(y[1]))
	uint128.Add64(&c, f)
	uint128.Mul64x64(&mul, uint64(x[1]), uint64(y[4]))
	uint128.Add(&c, &mul)
	uint128.Mul64x64(&mul, uint64(x[2]), uint64(y[3]))
	uint128.Add(&c, &mul)
	uint128.Mul64x64(&mul, uint64(x[3]), uint64(y[2]))
	uint128.Add(&c, &mul)

	f = uint128.Lo(&c)
	q1[0] |= Element((f << 32) & 0xffffffffffffff)
	q1[1] = Element((f >> 24) & 0xffffffff)
	f = uint128.Shr(&c, 56)

	uint128.Mul64x64(&c, uint64(x[4]), uint64(y[2]))
	uint128.Add64(&c, f)
	uint128.Mul64x64(&mul, uint64(x[2]), uint64(y[4]))
	uint128.Add(&c, &mul)
	uint128.Mul64x64(&mul, uint64(x[3]), uint64(y[3]))
	uint128.Add(&c, &mul)

	f = uint128.Lo(&c)
	q1[1] |= Element((f << 32) & 0xffffffffffffff)
	q1[2] = Element((f >> 24) & 0xffffffff)
	f = uint128.Shr(&c, 56)

	uint128.Mul64x64(&c, uint64(x[4]), uint64(y[3]))
	uint128.Add64(&c, f)
	uint128.Mul64x64(&mul, uint64(x[3]), uint64(y[4]))
	uint128.Add(&c, &mul)

	f = uint128.Lo(&c)
	q1[2] |= Element((f << 32) & 0xffffffffffffff)
	q1[3] = Element((f >> 24) & 0xffffffff)
	f = uint128.Shr(&c, 56)

	uint128.Mul64x64(&c, uint64(x[4]), uint64(y[4]))
	uint128.Add64(&c, f)

	f = uint128.Lo(&c)
	q1[3] |= Element((f << 32) & 0xffffffffffffff)
	q1[4] = Element((f >> 24) & 0xffffffff)
	f = uint128.Shr(&c, 56)

	q1[4] |= Element(f << 32)

	barrettReduce(r, &q1, &r1)
}

func Expand(out *Bignum256, in []byte) {
	// expand256_modm(bignum256modm out, const unsigned char *in, size_t len)
	var (
		work [64]byte
		x    [8]Element
	)

	copy(work[:], in)
	x[0] = Element(binary.LittleEndian.Uint64(work[0:]))
	x[1] = Element(binary.LittleEndian.Uint64(work[8:]))
	x[2] = Element(binary.LittleEndian.Uint64(work[16:]))
	x[3] = Element(binary.LittleEndian.Uint64(work[24:]))
	x[4] = Element(binary.LittleEndian.Uint64(work[32:]))
	x[5] = Element(binary.LittleEndian.Uint64(work[40:]))
	x[6] = Element(binary.LittleEndian.Uint64(work[48:]))
	x[7] = Element(binary.LittleEndian.Uint64(work[56:]))

	// r1 = (x mod 256^(32+1)) = x mod (2^8)(31+1) = x & ((1 << 264) - 1)
	out[0] = (x[0]) & 0xffffffffffffff
	out[1] = ((x[0] >> 56) | (x[1] << 8)) & 0xffffffffffffff
	out[2] = ((x[1] >> 48) | (x[2] << 16)) & 0xffffffffffffff
	out[3] = ((x[2] >> 40) | (x[3] << 24)) & 0xffffffffffffff
	out[4] = ((x[3] >> 32) | (x[4] << 32)) & 0x0000ffffffffff

	// under 252 bits, no need to reduce
	if len(in) < 32 {
		return
	}

	// q1 = x >> 248 = 264 bits
	var q1 Bignum256
	q1[0] = ((x[3] >> 56) | (x[4] << 8)) & 0xffffffffffffff
	q1[1] = ((x[4] >> 48) | (x[5] << 16)) & 0xffffffffffffff
	q1[2] = ((x[5] >> 40) | (x[6] << 24)) & 0xffffffffffffff
	q1[3] = ((x[6] >> 32) | (x[7] << 32)) & 0xffffffffffffff
	q1[4] = (x[7] >> 24)

	barrettReduce(out, &q1, out)
}

func ExpandRaw(out *Bignum256, in []byte) {
	// expand_raw256_modm(bignum256modm out, const unsigned char in[32])
	var x [4]Element

	_ = in[31]
	x[0] = Element(binary.LittleEndian.Uint64(in[0:8]))
	x[1] = Element(binary.LittleEndian.Uint64(in[8:16]))
	x[2] = Element(binary.LittleEndian.Uint64(in[16:24]))
	x[3] = Element(binary.LittleEndian.Uint64(in[24:32]))

	out[0] = (x[0]) & 0xffffffffffffff
	out[1] = ((x[0] >> 56) | (x[1] << 8)) & 0xffffffffffffff
	out[2] = ((x[1] >> 48) | (x[2] << 16)) & 0xffffffffffffff
	out[3] = ((x[2] >> 40) | (x[3] << 24)) & 0xffffffffffffff
	out[4] = (x[3] >> 32) & 0x000000ffffffff
}

func Contract(out []byte, in *Bignum256) {
	// contract256_modm(unsigned char out[32], const bignum256modm in)
	_ = out[31]
	binary.LittleEndian.PutUint64(out[0:8], uint64((in[0])|(in[1]<<56)))
	binary.LittleEndian.PutUint64(out[8:16], uint64((in[1]>>8)|(in[2]<<48)))
	binary.LittleEndian.PutUint64(out[16:24], uint64((in[2]>>16)|(in[3]<<40)))
	binary.LittleEndian.PutUint64(out[24:32], uint64((in[3]>>24)|(in[4]<<32)))
}

func ContractWindow4(r *[64]int8, in *Bignum256) {
	// contract256_window4_modm(signed char r[64], const bignum256modm in)
	var quads int
	for i := 0; i < 5; i++ {
		v := in[i]
		var m int
		if i == 4 {
			m = 8
		} else {
			m = 14
		}
		for j := 0; j < m; j++ {
			r[quads] = int8(v & 15)
			quads++
			v >>= 4
		}
	}

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
	// contract256_slidingwindow_modm(signed char r[256], const bignum256modm s, int windowsize)
	const soplen = 256
	var (
		v    Element
		bits int
	)

	for i := 0; i < 4; i++ {
		v = s[i]
		for j := 0; j < 56; j++ {
			r[bits] = int8(v & 1)
			bits++
			v >>= 1
		}
	}
	v = s[4]
	for j := 0; j < 32; j++ {
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

//
// helpers for batch verifcation, are allowed to be vartime
//
//
// Note: Unlike upstream, the `_batch` suffix for the calls has been
// replaced with `Vartime` for consistency and clarity.
//

// out = a - b, a must be larger than b
func SubVartime(out, a, b *Bignum256, limbSize int) {
	// sub256_modm_batch(bignum256modm out, const bignum256modm a, const bignum256modm b, size_t limbsize)
	var (
		carry Element
		i     int
	)

	switch limbSize {
	case 4:
		out[i] = (a[i] - b[i])
		carry = (out[i] >> 63)
		out[i] &= 0xffffffffffffff
		i++
		fallthrough
	case 3:
		out[i] = (a[i] - b[i]) - carry
		carry = (out[i] >> 63)
		out[i] &= 0xffffffffffffff
		i++
		fallthrough
	case 2:
		out[i] = (a[i] - b[i]) - carry
		carry = (out[i] >> 63)
		out[i] &= 0xffffffffffffff
		i++
		fallthrough
	case 1:
		out[i] = (a[i] - b[i]) - carry
		carry = (out[i] >> 63)
		out[i] &= 0xffffffffffffff
		i++
		fallthrough
	default:
		out[i] = (a[i] - b[i]) - carry
	}
}

// is a < b
func LessThanVartime(a, b *Bignum256, limbSize int) bool {
	// static int lt256_modm_batch(const bignum256modm a, const bignum256modm b, size_t limbsize)
	var (
		t, carry Element
		i        int
	)

	switch limbSize {
	case 4:
		t = (a[i] - b[i])
		carry = (t >> 63)
		i++
		fallthrough
	case 3:
		t = (a[i] - b[i]) - carry
		carry = (t >> 63)
		i++
		fallthrough
	case 2:
		t = (a[i] - b[i]) - carry
		carry = (t >> 63)
		i++
		fallthrough
	case 1:
		t = (a[i] - b[i]) - carry
		carry = (t >> 63)
		i++
		fallthrough
	case 0:
		t = (a[i] - b[i]) - carry
		carry = (t >> 63)
	}

	return carry != 0
}

// is a <= b
func LessThanOrEqualVartime(a, b *Bignum256, limbSize int) bool {
	// static int lte256_modm_batch(const bignum256modm a, const bignum256modm b, size_t limbsize)
	var (
		t, carry Element
		i        int
	)

	switch limbSize {
	case 4:
		t = (b[i] - a[i])
		carry = (t >> 63)
		i++
		fallthrough
	case 3:
		t = (b[i] - a[i]) - carry
		carry = (t >> 63)
		i++
		fallthrough
	case 2:
		t = (b[i] - a[i]) - carry
		carry = (t >> 63)
		i++
		fallthrough
	case 1:
		t = (b[i] - a[i]) - carry
		carry = (t >> 63)
		i++
		fallthrough
	case 0:
		t = (b[i] - a[i]) - carry
		carry = (t >> 63)
	}

	return carry == 0
}

// is a == 0
func IsZeroVartime(a *Bignum256) bool {
	// int iszero256_modm_batch(const bignum256modm a)
	for _, v := range a {
		if v != 0 {
			return false
		}
	}
	return true
}

// is a == 1
func IsOneVartime(a *Bignum256) bool {
	// int isone256_modm_batch(const bignum256modm a)
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

// can a fit in to (at most) 128 bits
func IsAtMost128bitsVartime(a *Bignum256) bool {
	// int isatmost128bits256_modm_batch(const bignum256modm a)
	mask := a[4] | a[3] | (a[2] & 0xffffffffff0000)

	return mask == 0
}

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

// +build amd64 go1.13,arm64 go1.13,ppc64le go1.13,ppc64 force64bit
// +build !force32bit

package curve25519

import (
	"encoding/binary"

	"github.com/oasisprotocol/ed25519/internal/uint128"
)

// Upstream: `curve25519-donna-64bit.h`

const (
	reduceMask51 = (uint64(1) << 51) - 1

	// multiples of p
	twoP0     = 0x0fffffffffffda
	twoP1234  = 0x0ffffffffffffe
	fourP0    = 0x1fffffffffffb4
	fourP1234 = 0x1ffffffffffffc
)

type Bignum25519 [5]uint64

// out = 0
func (out *Bignum25519) Reset() {
	// memset(out, 0, sizeof(bignum25519))
	for i := range out {
		out[i] = 0
	}
}

// out = in
func Copy(out, in *Bignum25519) {
	// curve25519_copy(bignum25519 out, const bignum25519 in)
	out[0] = in[0]
	out[1] = in[1]
	out[2] = in[2]
	out[3] = in[3]
	out[4] = in[4]
}

// out = a + b
func Add(out, a, b *Bignum25519) {
	// curve25519_add(bignum25519 out, const bignum25519 a, const bignum25519 b)
	out[0] = a[0] + b[0]
	out[1] = a[1] + b[1]
	out[2] = a[2] + b[2]
	out[3] = a[3] + b[3]
	out[4] = a[4] + b[4]
}

// out = a + b, where a and/or b are the result of a basic op (add,sub)
func AddAfterBasic(out, a, b *Bignum25519) {
	// curve25519_add_after_basic(bignum25519 out, const bignum25519 a, const bignum25519 b)
	out[0] = a[0] + b[0]
	out[1] = a[1] + b[1]
	out[2] = a[2] + b[2]
	out[3] = a[3] + b[3]
	out[4] = a[4] + b[4]
}

func AddReduce(out, a, b *Bignum25519) {
	// curve25519_add_reduce(bignum25519 out, const bignum25519 a, const bignum25519 b)
	out[0] = a[0] + b[0]
	c := out[0] >> 51
	out[0] &= reduceMask51

	out[1] = a[1] + b[1] + c
	c = out[1] >> 51
	out[1] &= reduceMask51

	out[2] = a[2] + b[2] + c
	c = out[2] >> 51
	out[2] &= reduceMask51

	out[3] = a[3] + b[3] + c
	c = out[3] >> 51
	out[3] &= reduceMask51

	out[4] = a[4] + b[4] + c
	c = out[4] >> 51
	out[4] &= reduceMask51

	out[0] += c * 19
}

// out = a - b
func Sub(out, a, b *Bignum25519) {
	// curve25519_sub(bignum25519 out, const bignum25519 a, const bignum25519 b)
	out[0] = a[0] + twoP0 - b[0]
	out[1] = a[1] + twoP1234 - b[1]
	out[2] = a[2] + twoP1234 - b[2]
	out[3] = a[3] + twoP1234 - b[3]
	out[4] = a[4] + twoP1234 - b[4]
}

// out = a - b, where a and/or b are the result of a basic op (add,sub)
func SubAfterBasic(out, a, b *Bignum25519) {
	// curve25519_sub_after_basic(bignum25519 out, const bignum25519 a, const bignum25519 b)
	out[0] = a[0] + fourP0 - b[0]
	out[1] = a[1] + fourP1234 - b[1]
	out[2] = a[2] + fourP1234 - b[2]
	out[3] = a[3] + fourP1234 - b[3]
	out[4] = a[4] + fourP1234 - b[4]
}

func SubReduce(out, a, b *Bignum25519) {
	// curve25519_sub_reduce(bignum25519 out, const bignum25519 a, const bignum25519 b)
	out[0] = a[0] + fourP0 - b[0]
	c := (out[0] >> 51)
	out[0] &= reduceMask51

	out[1] = a[1] + fourP1234 - b[1] + c
	c = (out[1] >> 51)
	out[1] &= reduceMask51

	out[2] = a[2] + fourP1234 - b[2] + c
	c = (out[2] >> 51)
	out[2] &= reduceMask51

	out[3] = a[3] + fourP1234 - b[3] + c
	c = (out[3] >> 51)
	out[3] &= reduceMask51

	out[4] = a[4] + fourP1234 - b[4] + c
	c = (out[4] >> 51)
	out[4] &= reduceMask51

	out[0] += c * 19
}

// out = -a
func Neg(out, a *Bignum25519) {
	// curve25519_neg(bignum25519 out, const bignum25519 a)
	out[0] = twoP0 - a[0]
	c := (out[0] >> 51)
	out[0] &= reduceMask51

	out[1] = twoP1234 - a[1] + c
	c = (out[1] >> 51)
	out[1] &= reduceMask51

	out[2] = twoP1234 - a[2] + c
	c = (out[2] >> 51)
	out[2] &= reduceMask51

	out[3] = twoP1234 - a[3] + c
	c = (out[3] >> 51)
	out[3] &= reduceMask51

	out[4] = twoP1234 - a[4] + c
	c = (out[4] >> 51)
	out[4] &= reduceMask51

	out[0] += c * 19
}

// out = a * b
func Mul(out, in2, in *Bignum25519) {
	// curve25519_mul(bignum25519 out, const bignum25519 in2, const bignum25519 in)

	// Note: This should be inlined where possible, but the Go compiler
	// thinks it is too complicated.
	//
	// See also: https://github.com/golang/go/issues/21536

	var (
		mul                uint128.Uint128
		t0, t1, t2, t3, t4 uint128.Uint128
	)

	r0, r1, r2, r3, r4 := in[0], in[1], in[2], in[3], in[4]
	s0, s1, s2, s3, s4 := in2[0], in2[1], in2[2], in2[3], in2[4]

	uint128.Mul64x64(&t0, r0, s0)

	uint128.Mul64x64(&t1, r0, s1)
	uint128.Mul64x64(&mul, r1, s0)
	uint128.Add(&t1, &mul)

	uint128.Mul64x64(&t2, r0, s2)
	uint128.Mul64x64(&mul, r2, s0)
	uint128.Add(&t2, &mul)
	uint128.Mul64x64(&mul, r1, s1)
	uint128.Add(&t2, &mul)

	uint128.Mul64x64(&t3, r0, s3)
	uint128.Mul64x64(&mul, r3, s0)
	uint128.Add(&t3, &mul)
	uint128.Mul64x64(&mul, r1, s2)
	uint128.Add(&t3, &mul)
	uint128.Mul64x64(&mul, r2, s1)
	uint128.Add(&t3, &mul)

	uint128.Mul64x64(&t4, r0, s4)
	uint128.Mul64x64(&mul, r4, s0)
	uint128.Add(&t4, &mul)
	uint128.Mul64x64(&mul, r3, s1)
	uint128.Add(&t4, &mul)
	uint128.Mul64x64(&mul, r1, s3)
	uint128.Add(&t4, &mul)
	uint128.Mul64x64(&mul, r2, s2)
	uint128.Add(&t4, &mul)

	r1 *= 19
	r2 *= 19
	r3 *= 19
	r4 *= 19

	uint128.Mul64x64(&mul, r4, s1)
	uint128.Add(&t0, &mul)
	uint128.Mul64x64(&mul, r1, s4)
	uint128.Add(&t0, &mul)
	uint128.Mul64x64(&mul, r2, s3)
	uint128.Add(&t0, &mul)
	uint128.Mul64x64(&mul, r3, s2)
	uint128.Add(&t0, &mul)

	uint128.Mul64x64(&mul, r4, s2)
	uint128.Add(&t1, &mul)
	uint128.Mul64x64(&mul, r2, s4)
	uint128.Add(&t1, &mul)
	uint128.Mul64x64(&mul, r3, s3)
	uint128.Add(&t1, &mul)

	uint128.Mul64x64(&mul, r4, s3)
	uint128.Add(&t2, &mul)
	uint128.Mul64x64(&mul, r3, s4)
	uint128.Add(&t2, &mul)

	uint128.Mul64x64(&mul, r4, s4)
	uint128.Add(&t3, &mul)

	r0 = uint128.Lo(&t0) & reduceMask51
	c := uint128.Shr(&t0, 51)

	uint128.Add64(&t1, c)
	r1 = uint128.Lo(&t1) & reduceMask51
	c = uint128.Shr(&t1, 51)

	uint128.Add64(&t2, c)
	r2 = uint128.Lo(&t2) & reduceMask51
	c = uint128.Shr(&t2, 51)

	uint128.Add64(&t3, c)
	r3 = uint128.Lo(&t3) & reduceMask51
	c = uint128.Shr(&t3, 51)

	uint128.Add64(&t4, c)
	r4 = uint128.Lo(&t4) & reduceMask51
	c = uint128.Shr(&t4, 51)

	r0 += c * 19
	c = r0 >> 51
	r0 = r0 & reduceMask51

	r1 += c

	out[0], out[1], out[2], out[3], out[4] = r0, r1, r2, r3, r4
}

// out = in^(2 * count)
func SquareTimes(out, in *Bignum25519, count int) {
	// curve25519_square_times(bignum25519 out, const bignum25519 in, uint64_t count)
	var t0, t1, t2, t3, t4 uint128.Uint128

	r0, r1, r2, r3, r4 := in[0], in[1], in[2], in[3], in[4]

	// Note: ed25519-donna uses do/while, but count is never 0.
	for i := 0; i < count; i++ {
		var mul uint128.Uint128

		d0 := r0 * 2
		d1 := r1 * 2
		d2 := r2 * 2 * 19
		d419 := r4 * 19
		d4 := d419 * 2

		uint128.Mul64x64(&t0, r0, r0)
		uint128.Mul64x64(&mul, d4, r1)
		uint128.Add(&t0, &mul)
		uint128.Mul64x64(&mul, d2, r3)
		uint128.Add(&t0, &mul)

		uint128.Mul64x64(&t1, d0, r1)
		uint128.Mul64x64(&mul, d4, r2)
		uint128.Add(&t1, &mul)
		uint128.Mul64x64(&mul, r3, r3*19)
		uint128.Add(&t1, &mul)

		uint128.Mul64x64(&t2, d0, r2)
		uint128.Mul64x64(&mul, r1, r1)
		uint128.Add(&t2, &mul)
		uint128.Mul64x64(&mul, d4, r3)
		uint128.Add(&t2, &mul)

		uint128.Mul64x64(&t3, d0, r3)
		uint128.Mul64x64(&mul, d1, r2)
		uint128.Add(&t3, &mul)
		uint128.Mul64x64(&mul, r4, d419)
		uint128.Add(&t3, &mul)

		uint128.Mul64x64(&t4, d0, r4)
		uint128.Mul64x64(&mul, d1, r3)
		uint128.Add(&t4, &mul)
		uint128.Mul64x64(&mul, r2, r2)
		uint128.Add(&t4, &mul)

		r0 = uint128.Lo(&t0) & reduceMask51

		r1 = uint128.Lo(&t1) & reduceMask51
		c := uint128.Shl(&t0, 13)
		r1 += c

		r2 = uint128.Lo(&t2) & reduceMask51
		c = uint128.Shl(&t1, 13)
		r2 += c

		r3 = uint128.Lo(&t3) & reduceMask51
		c = uint128.Shl(&t2, 13)
		r3 += c

		r4 = uint128.Lo(&t4) & reduceMask51
		c = uint128.Shl(&t3, 13)
		r4 += c

		c = uint128.Shl(&t4, 13)
		r0 += c * 19

		c = r0 >> 51
		r0 &= reduceMask51

		r1 += c
		c = r1 >> 51
		r1 &= reduceMask51

		r2 += c
		c = r2 >> 51
		r2 &= reduceMask51

		r3 += c
		c = r3 >> 51
		r3 &= reduceMask51

		r4 += c
		c = r4 >> 51
		r4 &= reduceMask51

		r0 += c * 19
	}

	out[0], out[1], out[2], out[3], out[4] = r0, r1, r2, r3, r4
}

func Square(out, in *Bignum25519) {
	// curve25519_square(bignum25519 out, const bignum25519 in)
	var t0, t1, t2, t3, t4, mul uint128.Uint128

	r0, r1, r2, r3, r4 := in[0], in[1], in[2], in[3], in[4]

	d0 := r0 * 2
	d1 := r1 * 2
	d2 := r2 * 2 * 19
	d419 := r4 * 19
	d4 := d419 * 2

	uint128.Mul64x64(&t0, r0, r0)
	uint128.Mul64x64(&mul, d4, r1)
	uint128.Add(&t0, &mul)
	uint128.Mul64x64(&mul, d2, r3)
	uint128.Add(&t0, &mul)

	uint128.Mul64x64(&t1, d0, r1)
	uint128.Mul64x64(&mul, d4, r2)
	uint128.Add(&t1, &mul)
	uint128.Mul64x64(&mul, r3, r3*19)
	uint128.Add(&t1, &mul)

	uint128.Mul64x64(&t2, d0, r2)
	uint128.Mul64x64(&mul, r1, r1)
	uint128.Add(&t2, &mul)
	uint128.Mul64x64(&mul, d4, r3)
	uint128.Add(&t2, &mul)

	uint128.Mul64x64(&t3, d0, r3)
	uint128.Mul64x64(&mul, d1, r2)
	uint128.Add(&t3, &mul)
	uint128.Mul64x64(&mul, r4, d419)
	uint128.Add(&t3, &mul)

	uint128.Mul64x64(&t4, d0, r4)
	uint128.Mul64x64(&mul, d1, r3)
	uint128.Add(&t4, &mul)
	uint128.Mul64x64(&mul, r2, r2)
	uint128.Add(&t4, &mul)

	r0 = uint128.Lo(&t0) & reduceMask51
	c := uint128.Shr(&t0, 51)

	uint128.Add64(&t1, c)
	r1 = uint128.Lo(&t1) & reduceMask51
	c = uint128.Shr(&t1, 51)

	uint128.Add64(&t2, c)
	r2 = uint128.Lo(&t2) & reduceMask51
	c = uint128.Shr(&t2, 51)

	uint128.Add64(&t3, c)
	r3 = uint128.Lo(&t3) & reduceMask51
	c = uint128.Shr(&t3, 51)

	uint128.Add64(&t4, c)
	r4 = uint128.Lo(&t4) & reduceMask51
	c = uint128.Shr(&t4, 51)

	r0 += c * 19
	c = r0 >> 51
	r0 = r0 & reduceMask51
	r1 += c

	out[0], out[1], out[2], out[3], out[4] = r0, r1, r2, r3, r4
}

// Take a little-endian, 32-byte number and expand it into polynomial form
func Expand(out *Bignum25519, in []byte) {
	// curve25519_expand(bignum25519 out, const unsigned char *in)
	_ = in[31]
	x0 := binary.LittleEndian.Uint64(in[0:8])
	x1 := binary.LittleEndian.Uint64(in[8:16])
	x2 := binary.LittleEndian.Uint64(in[16:24])
	x3 := binary.LittleEndian.Uint64(in[24:32])

	out[0] = x0 & reduceMask51
	x0 = (x0 >> 51) | (x1 << 13)

	out[1] = x0 & reduceMask51
	x1 = (x1 >> 38) | (x2 << 26)

	out[2] = x1 & reduceMask51
	x2 = (x2 >> 25) | (x3 << 39)

	out[3] = x2 & reduceMask51
	x3 = (x3 >> 12)

	out[4] = x3 & reduceMask51
}

// Take a fully reduced polynomial form number and contract it into a
// little-endian, 32-byte array
func Contract(out []byte, input *Bignum25519) {
	// curve25519_contract(unsigned char *out, const bignum25519 input)
	var t [5]uint64

	t[0], t[1], t[2], t[3], t[4] = input[0], input[1], input[2], input[3], input[4]

	contractCarry := func() {
		t[1] += t[0] >> 51
		t[0] &= reduceMask51

		t[2] += t[1] >> 51
		t[1] &= reduceMask51

		t[3] += t[2] >> 51
		t[2] &= reduceMask51

		t[4] += t[3] >> 51
		t[3] &= reduceMask51
	}

	contractCarryFull := func() {
		contractCarry()

		t[0] += 19 * (t[4] >> 51)
		t[4] &= reduceMask51
	}

	contractCarryFinal := func() {
		contractCarry()

		t[4] &= reduceMask51
	}

	contractCarryFull()
	contractCarryFull()

	// now t is between 0 and 2^255-1, properly carried.
	// case 1: between 0 and 2^255-20. case 2: between 2^255-19 and 2^255-1.
	t[0] += 19
	contractCarryFull()

	// now between 19 and 2^255-1 in both cases, and offset by 19.
	t[0] += (reduceMask51 + 1) - 19
	t[1] += (reduceMask51 + 1) - 1
	t[2] += (reduceMask51 + 1) - 1
	t[3] += (reduceMask51 + 1) - 1
	t[4] += (reduceMask51 + 1) - 1

	// now between 2^255 and 2^256-20, and offset by 2^255.
	contractCarryFinal()

	var idx int
	write51Full := func(n int, shift uint) {
		f := ((t[n] >> shift) | (t[n+1] << (51 - shift)))
		binary.LittleEndian.PutUint64(out[idx:], f)
		idx += 8
	}
	write51 := func(n int) {
		write51Full(n, uint(13*n))
	}
	write51(0)
	write51(1)
	write51(2)
	write51(3)
}

// if (iswap) swap(a, b)
func SwapConditional(a, b *Bignum25519, iswap uint64) {
	// curve25519_swap_conditional(bignum25519 a, bignum25519 b, uint64_t iswap)
	swap := uint64(-int64(iswap))

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
}

// Constants for `internals_test.go`
var (
	// largest result for each limb from a mult or square: all elements except r1 reduced, r1 overflowed as far as possible
	maxBignum = Bignum25519{
		0x7ffffffffffff, 0x8000000001230, 0x7ffffffffffff, 0x7ffffffffffff, 0x7ffffffffffff,
	}

	// (max_bignum + max_bignum)^2
	maxBignum2SquaredRaw = [32]byte{
		0x10, 0x05, 0x00, 0x00, 0x00, 0x00, 0x80, 0xdc, 0x51, 0x00, 0x00, 0x00, 0x00, 0x61, 0xed, 0x4a,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	// ((max_bignum + max_bignum) + max_bignum)^2
	maxBignum3SquaredRaw = [32]byte{
		0x64, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x20, 0x30, 0xb8, 0x00, 0x00, 0x00, 0x40, 0x1a, 0x96, 0xe8,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	// what max_bignum should fully reduce to
	maxBignumRaw = [32]byte{
		0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x91, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	// (max_bignum * max_bignum)
	maxBignumSquaredRaw = [32]byte{
		0x44, 0x01, 0x00, 0x00, 0x00, 0x00, 0x20, 0x77, 0x14, 0x00, 0x00, 0x00, 0x40, 0x58, 0xbb, 0x52,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
)

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

// Package ge25519 implements arithmetic on the twisted Edwards curve -x^2 + y^2 = 1 + dx^2y^2
// with d = -(121665/121666) = 37095705934669439343138083508754565189542113879843219016388785533085940283555
//
// Base point: (15112221349535400772501151409588531511454012693041857206046113283949847762202,46316835694926478169428394003475163141307993866256225615783033603165251855960);
package ge25519

import (
	"crypto/subtle"

	"github.com/oasisprotocol/ed25519/internal/curve25519"
	"github.com/oasisprotocol/ed25519/internal/modm"
)

// Upstream: `ed25519-donna-impl-base.h`

type Ge25519 struct {
	x curve25519.Bignum25519
	y curve25519.Bignum25519
	z curve25519.Bignum25519
	t curve25519.Bignum25519
}

func (r *Ge25519) X() *curve25519.Bignum25519 {
	return &r.x
}

func (r *Ge25519) Y() *curve25519.Bignum25519 {
	return &r.y
}

func (r *Ge25519) Z() *curve25519.Bignum25519 {
	return &r.z
}

func (r *Ge25519) Reset() {
	r.x.Reset()
	r.y.Reset()
	r.z.Reset()
	r.t.Reset()
}

type ge25519p1p1 struct {
	x curve25519.Bignum25519
	y curve25519.Bignum25519
	z curve25519.Bignum25519
	t curve25519.Bignum25519
}

type ge25519niels struct {
	ysubx curve25519.Bignum25519
	xaddy curve25519.Bignum25519
	t2d   curve25519.Bignum25519
}

type ge25519pniels struct {
	ysubx curve25519.Bignum25519
	xaddy curve25519.Bignum25519
	z     curve25519.Bignum25519
	t2d   curve25519.Bignum25519
}

//
// conversions
//

func p1p1ToPartial(r *Ge25519, p *ge25519p1p1) {
	// ge25519_p1p1_to_partial(ge25519 *r, const ge25519_p1p1 *p)
	curve25519.Mul(&r.x, &p.x, &p.t)
	curve25519.Mul(&r.y, &p.y, &p.z)
	curve25519.Mul(&r.z, &p.z, &p.t)
}

func p1p1ToFull(r *Ge25519, p *ge25519p1p1) {
	// ge25519_p1p1_to_full(ge25519 *r, const ge25519_p1p1 *p)
	curve25519.Mul(&r.x, &p.x, &p.t)
	curve25519.Mul(&r.y, &p.y, &p.z)
	curve25519.Mul(&r.z, &p.z, &p.t)
	curve25519.Mul(&r.t, &p.x, &p.y)
}

func fullToPniels(r *ge25519pniels, p *Ge25519) {
	// ge25519_full_to_pniels(ge25519_pniels *p, const ge25519 *r)

	// Note: Upstream's p/r being inconsistent with internal convention
	// is fixed for readability.

	curve25519.Sub(&r.ysubx, &p.y, &p.x)
	curve25519.Add(&r.xaddy, &p.y, &p.x)
	curve25519.Copy(&r.z, &p.z)
	curve25519.Mul(&r.t2d, &p.t, &ec2d)
}

//
// adding & doubling
//

func addP1p1(r *ge25519p1p1, p, q *Ge25519) {
	// ge25519_add_p1p1(ge25519_p1p1 *r, const ge25519 *p, const ge25519 *q)
	var a, b, c, d, t, u curve25519.Bignum25519

	curve25519.Sub(&a, &p.y, &p.x)
	curve25519.Add(&b, &p.y, &p.x)
	curve25519.Sub(&t, &q.y, &q.x)
	curve25519.Add(&u, &q.y, &q.x)
	curve25519.Mul(&a, &a, &t)
	curve25519.Mul(&b, &b, &u)
	curve25519.Mul(&c, &p.t, &q.t)
	curve25519.Mul(&c, &c, &ec2d)
	curve25519.Mul(&d, &p.z, &q.z)
	curve25519.Add(&d, &d, &d)
	curve25519.Sub(&r.x, &b, &a)
	curve25519.Add(&r.y, &b, &a)
	curve25519.AddAfterBasic(&r.z, &d, &c)
	curve25519.SubAfterBasic(&r.t, &d, &c)
}

func doubleP1p1(r *ge25519p1p1, p *Ge25519) {
	// ge25519_double_p1p1(ge25519_p1p1 *r, const ge25519 *p)
	var a, b, c curve25519.Bignum25519

	curve25519.Square(&a, &p.x)
	curve25519.Square(&b, &p.y)
	curve25519.Square(&c, &p.z)
	curve25519.AddReduce(&c, &c, &c)
	curve25519.Add(&r.x, &p.x, &p.y)
	curve25519.Square(&r.x, &r.x)
	curve25519.Add(&r.y, &b, &a)
	curve25519.Sub(&r.z, &b, &a)
	curve25519.SubAfterBasic(&r.x, &r.x, &r.y)
	curve25519.SubAfterBasic(&r.t, &c, &r.z)
}

func nielsAdd2P1p1Vartime(r *ge25519p1p1, p *Ge25519, q *ge25519niels, signbit uint8) {
	// ge25519_nielsadd2_p1p1(ge25519_p1p1 *r, const ge25519 *p, const ge25519_niels *q, unsigned char signbit)
	var a, b, c curve25519.Bignum25519

	// Note: The upstream code typecasts q and r to pointers to avoid
	// the conditionals, but having them is safe as this routine is
	// only called from `ge25519_double_scalarmult_vartime`.

	curve25519.Sub(&a, &p.y, &p.x)
	curve25519.Add(&b, &p.y, &p.x)
	if signbit == 0 {
		curve25519.Mul(&a, &a, &q.ysubx)
		curve25519.Mul(&r.x, &b, &q.xaddy)
	} else {
		curve25519.Mul(&a, &a, &q.xaddy)
		curve25519.Mul(&r.x, &b, &q.ysubx)
	}
	curve25519.Add(&r.y, &r.x, &a)
	curve25519.Sub(&r.x, &r.x, &a)
	curve25519.Mul(&c, &p.t, &q.t2d)
	curve25519.AddReduce(&r.t, &p.z, &p.z)
	curve25519.Copy(&r.z, &r.t)
	if signbit == 0 {
		curve25519.Add(&r.z, &r.z, &c)
		curve25519.Sub(&r.t, &r.t, &c)
	} else {
		curve25519.Add(&r.t, &r.t, &c)
		curve25519.Sub(&r.z, &r.z, &c)
	}
}

func pnielsAddP1P1Vartime(r *ge25519p1p1, p *Ge25519, q *ge25519pniels, signbit uint8) {
	// ge25519_pnielsadd_p1p1(ge25519_p1p1 *r, const ge25519 *p, const ge25519_pniels *q, unsigned char signbit)
	var a, b, c curve25519.Bignum25519

	// Note: The upstream code typecasts q and r to pointers to avoid
	// the conditionals, but having them is safe as this routine is
	// only called from `ge25519_double_scalarmult_vartime`.

	curve25519.Sub(&a, &p.y, &p.x)
	curve25519.Add(&b, &p.y, &p.x)
	if signbit == 0 {
		curve25519.Mul(&a, &a, &q.ysubx)
		curve25519.Mul(&r.x, &b, &q.xaddy)
	} else {
		curve25519.Mul(&a, &a, &q.xaddy)
		curve25519.Mul(&r.x, &b, &q.ysubx)
	}
	curve25519.Add(&r.y, &r.x, &a)
	curve25519.Sub(&r.x, &r.x, &a)
	curve25519.Mul(&c, &p.t, &q.t2d)
	curve25519.Mul(&r.t, &p.z, &q.z)
	curve25519.AddReduce(&r.t, &r.t, &r.t)
	curve25519.Copy(&r.z, &r.t)
	if signbit == 0 {
		curve25519.Add(&r.z, &r.z, &c)
		curve25519.Sub(&r.t, &r.t, &c)
	} else {
		curve25519.Add(&r.t, &r.t, &c)
		curve25519.Sub(&r.z, &r.z, &c)
	}
}

func doublePartial(r *Ge25519, p *Ge25519) {
	// ge25519_double_partial(ge25519 *r, const ge25519 *p)
	var t ge25519p1p1
	doubleP1p1(&t, p)
	p1p1ToPartial(r, &t)
}

func Double(r *Ge25519, p *Ge25519) {
	// ge25519_double(ge25519 *r, const ge25519 *p)
	var t ge25519p1p1
	doubleP1p1(&t, p)
	p1p1ToFull(r, &t)
}

func Add(r, p, q *Ge25519) {
	// ge25519_add(ge25519 *r, const ge25519 *p,  const ge25519 *q)
	var t ge25519p1p1
	addP1p1(&t, p, q)
	p1p1ToFull(r, &t)
}

func nielsAdd2(r *Ge25519, q *ge25519niels) {
	// ge25519_nielsadd2(ge25519 *r, const ge25519_niels *q)
	var a, b, c, e, f, g, h curve25519.Bignum25519

	curve25519.Sub(&a, &r.y, &r.x)
	curve25519.Add(&b, &r.y, &r.x)
	curve25519.Mul(&a, &a, &q.ysubx)
	curve25519.Mul(&e, &b, &q.xaddy)
	curve25519.Add(&h, &e, &a)
	curve25519.Sub(&e, &e, &a)
	curve25519.Mul(&c, &r.t, &q.t2d)
	curve25519.Add(&f, &r.z, &r.z)
	curve25519.AddAfterBasic(&g, &f, &c)
	curve25519.SubAfterBasic(&f, &f, &c)
	curve25519.Mul(&r.x, &e, &f)
	curve25519.Mul(&r.y, &h, &g)
	curve25519.Mul(&r.z, &g, &f)
	curve25519.Mul(&r.t, &e, &h)
}

func pnielsAdd(r *ge25519pniels, p *Ge25519, q *ge25519pniels) {
	// ge25519_pnielsadd(ge25519_pniels *r, const ge25519 *p, const ge25519_pniels *q)
	var a, b, c, x, y, z, t curve25519.Bignum25519

	curve25519.Sub(&a, &p.y, &p.x)
	curve25519.Add(&b, &p.y, &p.x)
	curve25519.Mul(&a, &a, &q.ysubx)
	curve25519.Mul(&x, &b, &q.xaddy)
	curve25519.Add(&y, &x, &a)
	curve25519.Sub(&x, &x, &a)
	curve25519.Mul(&c, &p.t, &q.t2d)
	curve25519.Mul(&t, &p.z, &q.z)
	curve25519.Add(&t, &t, &t)
	curve25519.AddAfterBasic(&z, &t, &c)
	curve25519.SubAfterBasic(&t, &t, &c)
	curve25519.Mul(&r.xaddy, &x, &t)
	curve25519.Mul(&r.ysubx, &y, &z)
	curve25519.Mul(&r.z, &z, &t)
	curve25519.Mul(&r.t2d, &x, &y)
	curve25519.Copy(&y, &r.ysubx)
	curve25519.Sub(&r.ysubx, &r.ysubx, &r.xaddy)
	curve25519.Add(&r.xaddy, &r.xaddy, &y)
	curve25519.Mul(&r.t2d, &r.t2d, &ec2d)
}

//
// pack & unpack
//

func Pack(r []byte, p *Ge25519) {
	// ge25519_pack(unsigned char r[32], const ge25519 *p)
	var (
		tx, ty, zi curve25519.Bignum25519
		parity     [32]byte
	)

	curve25519.Recip(&zi, &p.z)
	curve25519.Mul(&tx, &p.x, &zi)
	curve25519.Mul(&ty, &p.y, &zi)
	curve25519.Contract(r, &ty)
	curve25519.Contract(parity[:], &tx)
	r[31] ^= ((parity[0] & 1) << 7)
}

func UnpackNegativeVartime(r *Ge25519, p []byte) bool {
	// ge25519_unpack_negative_vartime(ge25519 *r, const unsigned char p[32])
	var (
		t, root, num, den, d3 curve25519.Bignum25519
		zero, check           [32]byte
		one                   = curve25519.Bignum25519{1}
		parity                = p[31] >> 7
	)

	curve25519.Expand(&r.y, p)
	curve25519.Copy(&r.z, &one)
	curve25519.Square(&num, &r.y)          // x = y^2
	curve25519.Mul(&den, &num, &ecd)       // den = dy^2
	curve25519.SubReduce(&num, &num, &r.z) // x = y^1 - 1
	curve25519.Add(&den, &den, &r.z)       // den = dy^2 + 1

	// Computation of sqrt(num/den)
	// 1.: computation of num^((p-5)/8)*den^((7p-35)/8) = (num*den^7)^((p-5)/8)
	curve25519.Square(&t, &den)
	curve25519.Mul(&d3, &t, &den)
	curve25519.Square(&r.x, &d3)
	curve25519.Mul(&r.x, &r.x, &den)
	curve25519.Mul(&r.x, &r.x, &num)
	curve25519.PowTwo252m3(&r.x, &r.x)

	// 2. computation of r.x = num * den^3 * (num*den^7)^((p-5)/8)
	curve25519.Mul(&r.x, &r.x, &d3)
	curve25519.Mul(&r.x, &r.x, &num)

	// 3. Check if either of the roots works:
	curve25519.Square(&t, &r.x)
	curve25519.Mul(&t, &t, &den)
	curve25519.SubReduce(&root, &t, &num)
	curve25519.Contract(check[:], &root)
	if subtle.ConstantTimeCompare(check[:], zero[:]) == 0 {
		curve25519.AddReduce(&t, &t, &num)
		curve25519.Contract(check[:], &t)
		if subtle.ConstantTimeCompare(check[:], zero[:]) == 0 {
			return false
		}
		curve25519.Mul(&r.x, &r.x, &sqrtNeg1)
	}

	curve25519.Contract(check[:], &r.x)
	if (check[0] & 1) == parity {
		curve25519.Copy(&t, &r.x)
		curve25519.Neg(&r.x, &t)
	}
	curve25519.Mul(&r.t, &r.x, &r.y)

	return true
}

//
// scalarmults
//

const (
	s1SWindowSize = 5
	s1TableSize   = 1 << (s1SWindowSize - 2)
	s2SWindowSize = 7
)

// computes [s1]p1 + [s2]basepoint
func DoubleScalarmultVartime(r, p1 *Ge25519, s1, s2 *modm.Bignum256) {
	// ge25519_double_scalarmult_vartime(ge25519 *r, const ge25519 *p1, const bignum256modm s1, const bignum256modm s2)
	var (
		slide1, slide2 [256]int8
		pre1           [s1TableSize]ge25519pniels
		d1             Ge25519
		t              ge25519p1p1
		i              int
	)

	modm.ContractSlidingWindow(&slide1, s1, s1SWindowSize)
	modm.ContractSlidingWindow(&slide2, s2, s2SWindowSize)

	Double(&d1, p1)
	fullToPniels(&pre1[0], p1)
	for i = 0; i < s1TableSize-1; i++ {
		pnielsAdd(&pre1[i+1], &d1, &pre1[i])
	}

	// set neutral
	r.Reset()
	r.y[0] = 1
	r.z[0] = 1

	i = 255
	for (i >= 0) && (slide1[i]|slide2[i]) == 0 {
		i--
	}

	abs := func(n int8) int {
		if n < 0 {
			return -int(n)
		}
		return int(n)
	}

	for ; i >= 0; i-- {
		doubleP1p1(&t, r)

		if slide1[i] != 0 {
			p1p1ToFull(r, &t)
			pnielsAddP1P1Vartime(&t, r, &pre1[abs(slide1[i])/2], uint8(slide1[i])>>7)
		}

		if slide2[i] != 0 {
			p1p1ToFull(r, &t)
			nielsAdd2P1p1Vartime(&t, r, &nielsSlidingMultiples[abs(slide2[i])/2], uint8(slide2[i])>>7)
		}

		p1p1ToPartial(r, &t)
	}
}

// computes [s]basepoint
func ScalarmultBaseNiels(r *Ge25519, basepointTable *[256][96]byte, s *modm.Bignum256) {
	// ge25519_scalarmult_base_niels(ge25519 *r, const uint8_t basepoint_table[256][96], const bignum256modm s)
	var (
		b [64]int8
		t ge25519niels
	)

	modm.ContractWindow4(&b, s)

	scalarmultBaseChooseNiels(&t, basepointTable, 0, b[1])
	curve25519.SubReduce(&r.x, &t.xaddy, &t.ysubx)
	curve25519.AddReduce(&r.y, &t.xaddy, &t.ysubx)
	r.z.Reset()
	curve25519.Copy(&r.t, &t.t2d)
	r.z[0] = 2
	for i := 3; i < 64; i += 2 {
		scalarmultBaseChooseNiels(&t, basepointTable, i/2, b[i])
		nielsAdd2(r, &t)
	}
	doublePartial(r, r)
	doublePartial(r, r)
	doublePartial(r, r)
	Double(r, r)
	scalarmultBaseChooseNiels(&t, basepointTable, 0, b[0])
	curve25519.Mul(&t.t2d, &t.t2d, &ecd)
	nielsAdd2(r, &t)
	for i := 2; i < 64; i += 2 {
		scalarmultBaseChooseNiels(&t, basepointTable, i/2, b[i])
		nielsAdd2(r, &t)
	}

	for i := range b {
		b[i] = 0
	}
}

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

package curve25519

// Upstream: `curve25519-donna-helpers.h`

// In:  b =   2^5 - 2^0
// Out: b = 2^250 - 2^0
func powTwo5two0Two250mtwo0(b *Bignum25519) {
	// curve25519_pow_two5mtwo0_two250mtwo0(bignum25519 b)
	var t0, c Bignum25519

	// 2^5  - 2^0
	SquareTimes(&t0, b, 5)    // 2^10 - 2^5
	Mul(b, &t0, b)            // 2^10 - 2^0
	SquareTimes(&t0, b, 10)   // 2^20 - 2^10
	Mul(&c, &t0, b)           // 2^20 - 2^0
	SquareTimes(&t0, &c, 20)  // 2^40 - 2^20
	Mul(&t0, &t0, &c)         // 2^40 - 2^0
	SquareTimes(&t0, &t0, 10) // 2^50 - 2^10
	Mul(b, &t0, b)            // 2^50 - 2^0
	SquareTimes(&t0, b, 50)   // 2^100 - 2^50
	Mul(&c, &t0, b)           // 2^100 - 2^0
	SquareTimes(&t0, &c, 100) // 2^200 - 2^100
	Mul(&t0, &t0, &c)         // 2^200 - 2^0
	SquareTimes(&t0, &t0, 50) // 2^250 - 2^50
	Mul(b, &t0, b)            // 2^250 - 2^0
}

// z^(p - 2) = z(2^255 - 21)
func Recip(out, z *Bignum25519) {
	// curve25519_recip(bignum25519 out, const bignum25519 z)
	var a, b, t0 Bignum25519

	SquareTimes(&a, z, 1)      // 2, a = 2
	SquareTimes(&t0, &a, 2)    // 8
	Mul(&b, &t0, z)            // 9, b = 9
	Mul(&a, &b, &a)            // 11, a = 11
	SquareTimes(&t0, &a, 1)    // 22
	Mul(&b, &t0, &b)           // 2^5 - 2^0 = 31
	powTwo5two0Two250mtwo0(&b) // 2^250 - 2^0
	SquareTimes(&b, &b, 5)     // 2^255 - 2^5
	Mul(out, &b, &a)           // 2^255 - 21
}

// z^((p-5)/8) = z^(2^252 - 3)
func PowTwo252m3(two252m3, z *Bignum25519) {
	// curve25519_pow_two252m3(bignum25519 two252m3, const bignum25519 z)
	var b, c, t0 Bignum25519

	SquareTimes(&c, z, 1)      // 2, c=2
	SquareTimes(&t0, &c, 2)    // 8, t0=8
	Mul(&b, &t0, z)            // 9, b = 9
	Mul(&c, &b, &c)            // 11, c = 11
	SquareTimes(&t0, &c, 1)    // 22
	Mul(&b, &t0, &b)           // 2^5 - 2^0 = 31
	powTwo5two0Two250mtwo0(&b) // 2^250 - 2^0
	SquareTimes(&b, &b, 2)     // 2^252 - 2^2
	Mul(two252m3, &b, z)       // 2^252 - 3
}

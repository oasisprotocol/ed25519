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

// Package uint128 provides a basic unsigned 128 bit integer implementation.
package uint128

import "math/bits"

// Upstream: `ed25519-donna-portable.h`

// Uint128 is an unsigned 128 bit integer represented as 2 uint64 limbs.
type Uint128 struct {
	hi uint64
	lo uint64
}

// Mul sets `out` to the full 128 bit result of `a * b`.
func Mul64x64(out *Uint128, a, b uint64) {
	// mul64x64_128(out,a,b)
	out.hi, out.lo = bits.Mul64(a, b)
}

// Shr returns the low 64 bits of `a >> shift`.
func Shr(a *Uint128, shift uint64) uint64 {
	// shr128(out, in, shift)
	return (a.hi << (64 - shift)) | (a.lo >> shift)
}

// Shl returns the high 64 bits of `a << shift`.
func Shl(a *Uint128, shift uint64) uint64 {
	// shl128(out, in, shift)
	return (a.hi << shift) | (a.lo >> (64 - shift))
}

// Add sets `a` to the full 128 bit result of `a + b`.
func Add(a, b *Uint128) {
	// add128(a,b)
	var carry uint64
	a.lo, carry = bits.Add64(a.lo, b.lo, 0)
	a.hi, _ = bits.Add64(a.hi, b.hi, carry)
}

// Add64 sets `a` to the full 128 bit result of `a + b`.
func Add64(a *Uint128, b uint64) {
	// add128_64(a, b)
	var carry uint64
	a.lo, carry = bits.Add64(a.lo, b, 0)
	a.hi, _ = bits.Add64(a.hi, 0, carry)
}

// Lo returns the low 64 bits of `a`.
func Lo(a *Uint128) uint64 {
	// lo128(a)
	return a.lo
}

// Hi returns the high 64 bits of `a`.
func Hi(a *Uint128) uint64 {
	// hi128(a)
	return a.hi
}

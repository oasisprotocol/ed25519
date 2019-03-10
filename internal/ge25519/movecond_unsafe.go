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

// +build amd64,noasm 386 ppc64le
// +build !appengine

package ge25519

import "unsafe"

func moveConditionalBytes(out, in *[96]byte, flag uint64) {
	// curve25519_move_conditional_bytes(uint8_t out[96], const uint8_t in[96], uint64_t flag)
	inq := (*[12]uint64)(unsafe.Pointer(&in[0]))
	outq := (*[12]uint64)(unsafe.Pointer(&out[0]))

	var (
		nb = flag - 1
		b  = ^nb
	)
	outq[0] = (outq[0] & nb) | (inq[0] & b)
	outq[1] = (outq[1] & nb) | (inq[1] & b)
	outq[2] = (outq[2] & nb) | (inq[2] & b)
	outq[3] = (outq[3] & nb) | (inq[3] & b)
	outq[4] = (outq[4] & nb) | (inq[4] & b)
	outq[5] = (outq[5] & nb) | (inq[5] & b)
	outq[6] = (outq[6] & nb) | (inq[6] & b)
	outq[7] = (outq[7] & nb) | (inq[7] & b)
	outq[8] = (outq[8] & nb) | (inq[8] & b)
	outq[9] = (outq[9] & nb) | (inq[9] & b)
	outq[10] = (outq[10] & nb) | (inq[10] & b)
	outq[11] = (outq[11] & nb) | (inq[11] & b)
}

// Copyright (c) 2020 Oasis Labs Inc.  All rights reserved.
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

package ed25519

import (
	"compress/gzip"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"testing"
)

type zip215TestVector [2]string

func (tc zip215TestVector) Run(t *testing.T, isBatch bool) {
	msg := []byte("Zcash")
	rawPk, err := hex.DecodeString(tc[0])
	if err != nil {
		t.Fatalf("failed to decode public key: %v", err)
	}
	sig, err := hex.DecodeString(tc[1])
	if err != nil {
		t.Fatalf("failed to decode signature: %v", err)
	}

	pk := PublicKey(rawPk)
	opts := &Options{
		ZIP215Verify: true,
	}

	var sigOk bool
	switch isBatch {
	case false:
		sigOk = VerifyWithOptions(pk, msg, sig, opts)
	case true:
		var pks []PublicKey
		var sigs, msgs [][]byte
		for i := 0; i < minBatchSize*2; i++ {
			pks = append(pks, pk)
			msgs = append(msgs, msg)
			sigs = append(sigs, sig)
		}

		var valid []bool
		sigOk, valid, err = VerifyBatch(rand.Reader, pks, msgs, sigs, opts)
		if err != nil {
			t.Fatal(err)
		}
		for i, v := range valid {
			if v != sigOk {
				t.Fatalf("sigOk != valid[%d]", i)
			}
		}
	}

	if !sigOk {
		t.Fatalf("failed to verify signature")
	}
}

func TestZIP215(t *testing.T) {
	f, err := os.Open("testdata/zip215.json.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rd, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer rd.Close()

	var testVectors []zip215TestVector
	dec := json.NewDecoder(rd)
	if err = dec.Decode(&testVectors); err != nil {
		t.Fatal(err)
	}

	for idx, tc := range testVectors {
		n := fmt.Sprintf("TestCase_%d", idx)
		t.Run(n, func(t *testing.T) {
			tc.Run(t, false)
		})
		t.Run(n+"_Batch", func(t *testing.T) {
			tc.Run(t, true)
		})
	}
}

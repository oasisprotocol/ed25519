// Copyright (c) 2016 The Go Authors. All rights reserved.
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
//    * Neither the name of Google Inc. nor the names of its
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

// Package ed25519 implements the Ed25519 signature algorithm. See
// https://ed25519.cr.yp.to/.
//
// These functions are also compatible with the “Ed25519” function defined in
// RFC 8032. However, unlike RFC 8032's formulation, this package's private key
// representation includes a public key suffix to make multiple signing
// operations with the same key more efficient. This package refers to the RFC
// 8032 private key as the “seed”.
package ed25519

import (
	"bytes"
	"crypto"
	cryptorand "crypto/rand"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"io"
	"strconv"

	"github.com/oasislabs/ed25519/internal/ge25519"
	"github.com/oasislabs/ed25519/internal/modm"
)

const (
	// PublicKeySize is the size, in bytes, of public keys as used in this package.
	PublicKeySize = 32

	// PrivateKeySize is the size, in bytes, of private keys as used in this package.
	PrivateKeySize = 64

	// SignatureSize is the size, in bytes, of signatures generated and verified by this package.
	SignatureSize = 64

	// SeedSize is the size, in bytes, of private key seeds. These are the private key representations used by RFC 8032.
	SeedSize = 32
)

var _ crypto.Signer = (PrivateKey)(nil)

// PrivateKey is the type of Ed25519 private keys. It implements crypto.Signer.
type PrivateKey []byte

// Public returns the PublicKey corresponding to priv.
func (priv PrivateKey) Public() crypto.PublicKey {
	pub := make([]byte, PublicKeySize)
	copy(pub, priv[SeedSize:])
	return PublicKey(pub)
}

// Seed returns the private key seed corresponding to priv. It is provided for
// interoperability with RFC 8032. RFC 8032's private keys correspond to seeds
// in this package.
func (priv PrivateKey) Seed() []byte {
	s := make([]byte, SeedSize)
	copy(s, priv[:SeedSize])
	return s
}

// Sign signs the given message with priv. rand is ignored. If opts.HashFunc()
// is crypto.SHA512, the pre-hashed variant Ed25519ph is used and message is
// expected to be a SHA-512 hash, otherwise opts.HashFunc() must be
// crypto.Hash(0) and the message must not be hashed, as Ed25519 performs two
// passes over messages to be signed.
func (priv PrivateKey) Sign(rand io.Reader, message []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	switch opts.HashFunc() {
	case crypto.SHA512:
		if l := len(message); l != sha512.Size {
			return nil, errors.New("ed25519: bad message hash length: " + strconv.Itoa(l))
		}
		return sign(priv, message, fPh, nil), nil
	case crypto.Hash(0):
		return Sign(priv, message), nil
	default:
		return nil, errors.New("ed25519: expected opts zero (unhashed message, for standard Ed25519) or SHA-512 (for Ed25519ph)")
	}
}

// PublicKey is the type of Ed25519 public keys.
type PublicKey []byte

// Sign signs the message with privateKey and returns a signature. It will
// panic if len(privateKey) is not PrivateKeySize.
func Sign(privateKey PrivateKey, message []byte) []byte {
	return sign(privateKey, message, fPure, nil)
}

func sign(privateKey PrivateKey, message []byte, f dom2Flag, c []byte) []byte {
	if l := len(privateKey); l != PrivateKeySize {
		panic("ed25519: bad private key length: " + strconv.Itoa(l))
	}

	var (
		extsk, hashr, hram [64]byte
		r, S, a            modm.Bignum256
		R                  ge25519.Ge25519

		RS [SignatureSize]byte
	)

	h := sha512.New()
	_, _ = h.Write(privateKey[:32])
	h.Sum(extsk[:0])
	extsk[0] &= 248
	extsk[31] &= 127
	extsk[31] |= 64

	// r = H(aExt[32..64], m)
	h.Reset()
	if f != fPure {
		writeDom2(h, f, c)
	}
	_, _ = h.Write(extsk[32:])
	_, _ = h.Write(message)
	h.Sum(hashr[:0])
	modm.Expand(&r, hashr[:])

	// R = rB
	ge25519.ScalarmultBaseNiels(&R, &ge25519.NielsBaseMultiples, &r)
	ge25519.Pack(RS[:], &R)

	// S = H(R,A,m)..
	h.Reset()
	if f != fPure {
		writeDom2(h, f, c)
	}
	_, _ = h.Write(RS[:32])
	_, _ = h.Write(privateKey[32:])
	_, _ = h.Write(message)
	h.Sum(hram[:0])
	modm.Expand(&S, hram[:])

	// S = H(R,A,m)a
	modm.Expand(&a, extsk[:32])
	modm.Mul(&S, &S, &a)

	// S = (r + H(R,A,m)a)
	modm.Add(&S, &S, &r)

	// S = (r + H(R,A,m)a) mod L
	modm.Contract(RS[32:], &S)

	h.Reset()
	a.Reset()
	for i := range extsk {
		extsk[i] = 0
	}

	return RS[:]
}

// Verify reports whether sig is a valid signature of message by publicKey. It
// will panic if len(publicKey) is not PublicKeySize.
func Verify(publicKey PublicKey, message, sig []byte) bool {
	return verify(publicKey, message, sig, fPure, nil)
}

func verify(publicKey PublicKey, message, sig []byte, f dom2Flag, c []byte) bool {
	if l := len(publicKey); l != PublicKeySize {
		panic("ed25519: bad public key length: " + strconv.Itoa(l))
	}

	var (
		hash    [64]byte
		checkR  [32]byte
		R, A    ge25519.Ge25519
		hram, S modm.Bignum256
	)

	if len(sig) != SignatureSize || (sig[63]&224 != 0) || !ge25519.UnpackNegativeVartime(&A, publicKey) {
		return false
	}

	// hram = H(R,A,m)
	h := sha512.New()
	if f != fPure {
		writeDom2(h, f, c)
	}
	_, _ = h.Write(sig[:32])
	_, _ = h.Write(publicKey[:])
	_, _ = h.Write(message)
	h.Sum(hash[:0])
	modm.Expand(&hram, hash[:])

	// https://tools.ietf.org/html/rfc8032#section-5.1.7 requires that s be in
	// the range [0, order) in order to prevent signature malleability.
	if !scMinimal(sig[32:]) {
		return false
	}

	// S
	modm.Expand(&S, sig[32:])

	// SB - H(R,A,m)A
	ge25519.DoubleScalarmultVartime(&R, &A, &hram, &S)
	ge25519.Pack(checkR[:], &R)

	// check that R = SB - H(R,A,m)A
	return bytes.Equal(checkR[:], sig[:32])
}

// VerifyHashed reports whether sig is a valid Ed25519ph signature by publicKey
// of the SHA-512 digest hash. It will panic if len(publicKey) is not
// PublicKeySize or if len(hash) is not sha512.Size.
func VerifyHashed(publicKey PublicKey, hash, sig []byte) bool {
	if l := len(hash); l != sha512.Size {
		panic("ed25519: bad message hash length: " + strconv.Itoa(l))
	}
	return verify(publicKey, hash, sig, fPh, nil)
}

// NewKeyFromSeed calculates a private key from a seed. It will panic if
// len(seed) is not SeedSize. This function is provided for interoperability
// with RFC 8032. RFC 8032's private keys correspond to seeds in this
// package.
func NewKeyFromSeed(seed []byte) PrivateKey {
	if l := len(seed); l != SeedSize {
		panic("ed25519: bad seed length: " + strconv.Itoa(l))
	}

	// `sha512.Sum512` does not call d.Reset().
	var digest [64]byte
	h := sha512.New()
	_, _ = h.Write(seed)
	h.Sum(digest[:0])
	h.Reset()

	digest[0] &= 248
	digest[31] &= 127
	digest[31] |= 64

	var (
		a              modm.Bignum256
		A              ge25519.Ge25519
		publicKeyBytes [32]byte
	)
	modm.Expand(&a, digest[:32])
	ge25519.ScalarmultBaseNiels(&A, &ge25519.NielsBaseMultiples, &a)
	ge25519.Pack(publicKeyBytes[:], &A)

	privateKey := make([]byte, PrivateKeySize)
	copy(privateKey, seed)
	copy(privateKey[32:], publicKeyBytes[:])

	for i := range digest {
		digest[i] = 0
	}
	a.Reset()

	return privateKey
}

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error) {
	if rand == nil {
		rand = cryptorand.Reader
	}

	seed := make([]byte, SeedSize)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, nil, err
	}

	privateKey := NewKeyFromSeed(seed)
	publicKey := make([]byte, PublicKeySize)
	copy(publicKey, privateKey[32:])

	for i := range seed {
		seed[i] = 0
	}

	return publicKey, privateKey, nil
}

// order is the order of Curve25519 in little-endian form.
var order = [4]uint64{0x5812631a5cf5d3ed, 0x14def9dea2f79cd6, 0, 0x1000000000000000}

// scMinimal returns true if the given scalar is less than the order of the
// curve.
func scMinimal(scalar []byte) bool {
	for i := 3; ; i-- {
		v := binary.LittleEndian.Uint64(scalar[i*8:])
		if v > order[i] {
			return false
		} else if v < order[i] {
			break
		} else if i == 0 {
			return false
		}
	}

	return true
}

type dom2Flag byte

const (
	fCtx  dom2Flag = 0
	fPh   dom2Flag = 1
	fPure dom2Flag = 255 // Not in RFC, for implementation purposes.

	dom2Prefix = "SigEd25519 no Ed25519 collisions"
)

func writeDom2(w io.Writer, f dom2Flag, c []byte) {
	cLen := len(c)
	if cLen > ContextMaxSize {
		panic("ed25519: bad context length: " + strconv.Itoa(cLen))
	}

	_, _ = w.Write([]byte(dom2Prefix))
	_, _ = w.Write([]byte{byte(f), byte(cLen)})
	_, _ = w.Write(c)
}

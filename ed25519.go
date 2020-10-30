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

	"github.com/oasisprotocol/ed25519/internal/ge25519"
	"github.com/oasisprotocol/ed25519/internal/modm"
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

	// ContextMaxSize is the maximum allowed context length for Ed25519ctx.
	ContextMaxSize = 255
)

var _ crypto.Signer = (PrivateKey)(nil)

// Options can be used with PrivateKey.Sign or VerifyWithOptions
// to select Ed25519 variants.
type Options struct {
	// Hash can be crypto.Hash(0) for Ed25519/Ed25519ctx, or crypto.SHA512
	// for Ed25519ph.
	Hash crypto.Hash

	// Context is an optional domain separation context for Ed25519ph and
	// Ed25519ctx. It must be less than or equal to ContextMaxSize
	// in length.
	//
	// Warning: If Hash is crypto.Hash(0) and Context is a zero length
	// string, plain Ed25519 will be used instead of Ed25519ctx.
	Context string

	// ZIP215Verify specifies that verification should follow Zcash's
	// ZIP-215 semantics.
	ZIP215Verify bool
}

// HashFunc returns an identifier for the hash function used to produce
// the message pased to Signer.Sign. For the Ed25519 family this must
// be crypto.Hash(0) for Ed25519/Ed25519ctx, or crypto.SHA512 for
// Ed25519ph.
func (opt *Options) HashFunc() crypto.Hash {
	return opt.Hash
}

func (opt *Options) unwrap() (dom2Flag, []byte, error) {
	var (
		context []byte
		f       dom2Flag = fPure
	)

	if l := len(opt.Context); l > 0 {
		if l > ContextMaxSize {
			return f, nil, errors.New("ed25519: bad context length: " + strconv.Itoa(l))
		}

		context = []byte(opt.Context)

		// This disallows Ed25519ctx with a 0 length context, which is
		// technically allowed by the RFC ("SHOULD NOT be empty"), but
		// is discouraged and somewhat nonsensical anyway.
		f = fCtx
	}

	return f, context, nil
}

func checkHash(f dom2Flag, message []byte, hashFunc crypto.Hash) (dom2Flag, error) {
	switch hashFunc {
	case crypto.SHA512:
		if l := len(message); l != sha512.Size {
			return f, errors.New("ed25519: bad message hash length: " + strconv.Itoa(l))
		}
		f = fPh
	case crypto.Hash(0):
	default:
		return f, errors.New("ed25519: expected opts HashFunc zero (unhashed message, for Ed25519/Ed25519ctx) or SHA-512 (for Ed25519ph)")
	}

	return f, nil
}

// PrivateKey is the type of Ed25519 private keys. It implements crypto.Signer.
type PrivateKey []byte

// Public returns the PublicKey corresponding to priv.
func (priv PrivateKey) Public() crypto.PublicKey {
	pub := make([]byte, PublicKeySize)
	copy(pub, priv[SeedSize:])
	return PublicKey(pub)
}

// Equal reports whether priv and x have the same value.
func (priv PrivateKey) Equal(x crypto.PrivateKey) bool {
	xx, ok := x.(PrivateKey)
	if !ok {
		return false
	}
	return bytes.Equal(priv, xx)
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
	var (
		context []byte
		f       dom2Flag = fPure
	)
	if o, ok := opts.(*Options); ok {
		f, context, err = o.unwrap()
		if err != nil {
			return nil, err
		}
	}

	f, err = checkHash(f, message, opts.HashFunc())
	if err != nil {
		return nil, err
	}

	return sign(priv, message, f, context), nil
}

// PublicKey is the type of Ed25519 public keys.
type PublicKey []byte

// Any methods implemented on PublicKey might need to also be implemented on
// PrivateKey, as the latter embeds the former and will expose its methods.

// Equal reports whether pub and x have the same value.
func (pub PublicKey) Equal(x crypto.PublicKey) bool {
	xx, ok := x.(PublicKey)
	if !ok {
		return false
	}
	return bytes.Equal(pub, xx)
}

// IsSmallOrder returns true iff a Public Key is a small order point.
// This routine will panic if the public key length is invalid.
func (pub PublicKey) IsSmallOrder() bool {
	if l := len(pub); l != PublicKeySize {
		panic("ed25519: bad public key length: " + strconv.Itoa(l))
	}

	return isSmallOrderVartime(pub)
}

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
	return verify(publicKey, message, sig, fPure, nil, false)
}

func verify(publicKey PublicKey, message, sig []byte, f dom2Flag, c []byte, zip215 bool) bool {
	if l := len(publicKey); l != PublicKeySize {
		panic("ed25519: bad public key length: " + strconv.Itoa(l))
	}

	// Reject small order A to make the scheme strongly binding.
	if !zip215 && isSmallOrderVartime(publicKey) {
		return false
	}

	var (
		hash                [64]byte
		Rproj, R, A, checkR ge25519.Ge25519
		hram, S             modm.Bignum256
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

	if !ge25519.UnpackVartime(&checkR, sig[:32]) {
		return false
	}

	// S
	modm.Expand(&S, sig[32:])

	// SB - H(R,A,m)A
	ge25519.DoubleScalarmultVartime(&Rproj, &A, &hram, &S)
	ge25519.ProjectiveToExtended(&R, &Rproj)

	// check that [8](R - (SB - H(R,A,m)A)) == 0
	return ge25519.CofactorEqual(&R, &checkR)
}

// VerifyWithOptions reports whether sig is a valid Ed25519 signature by
// publicKey with the extra Options to support Ed25519ph (pre-hashed by
// SHA-512) or Ed25519ctx (includes a domain separation context). It
// will panic if len(publicKey) is not PublicKeySize, len(message) is
// not sha512.Size (if pre-hashed), or len(opts.Context) is greater than
// ContextMaxSize.
func VerifyWithOptions(publicKey PublicKey, message, sig []byte, opts *Options) bool {
	ok, err := verifyWithOptionsNoPanic(publicKey, message, sig, opts)
	if err != nil {
		panic(err)
	}

	return ok
}

func verifyWithOptionsNoPanic(publicKey PublicKey, message, sig []byte, opts *Options) (bool, error) {
	f, context, err := opts.unwrap()
	if err != nil {
		return false, err
	}

	f, err = checkHash(f, message, opts.HashFunc())
	if err != nil {
		return false, err
	}

	// verify will panic (for api compatibility with the runtime
	// package), so do the check before calling the routine.
	if l := len(publicKey); l != PublicKeySize {
		return false, errors.New("ed25519: bad public key length: " + strconv.Itoa(l))
	}

	return verify(publicKey, message, sig, f, context, opts.ZIP215Verify), nil
}

// NewKeyFromSeed calculates a private key from a seed. It will panic if
// len(seed) is not SeedSize. This function is provided for interoperability
// with RFC 8032. RFC 8032's private keys correspond to seeds in this
// package.
func NewKeyFromSeed(seed []byte) PrivateKey {
	if l := len(seed); l != SeedSize {
		panic("ed25519: bad seed length: " + strconv.Itoa(l))
	}

	// `sha512.Sum512` does not call d.Reset(), but it's somewhat of a
	// moot point because the runtime library's SHA-512 implementation's
	// `Reset()` method doesn't actually clear the buffer currently.
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
	if scalar[31]&240 == 0 {
		// 4 most significant bits unset, succeed fast
		return true
	}
	if scalar[31]&244 != 0 {
		// Any of the 3 most significant bits set, fail fast
		return false
	}

	// 4th most significant bit set (unlikely), actually check vs order
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

func isSmallOrderVartime(s []byte) bool {
	var t1, t2 ge25519.Ge25519

	if !ge25519.UnpackVartime(&t1, s) {
		panic("ed25519/isSmallOrderVartime: failed to unpack")
	}

	ge25519.CofactorMultiply(&t2, &t1)

	return ge25519.IsNeutralVartime(&t2)
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

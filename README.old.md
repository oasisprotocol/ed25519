### ed25519 - Optimized ed25519 for Go

[![Build status][github-ci-tests-badge]][github-ci-tests-link]
[![GoDoc][godoc-badge]][godoc-link]

[github-ci-tests-badge]: https://github.com/oasisprotocol/ed25519/workflows/ci-tests/badge.svg
[github-ci-tests-link]: https://github.com/oasisprotocol/ed25519/actions?query=workflow:ci-tests
[godoc-badge]: https://godoc.org/github.com/oasisprotocol/ed25519?status.svg
[godoc-link]: https://godoc.org/github.com/oasisprotocol/ed25519

This package provides a mostly drop-in replacement for
`golang.org/x/crypto/ed25519` with the aim to improve performance,
primarily on systems with a low cost `64 bit x 64 bit = 128 bit` multiply
operation.

This implementation is derived from Andrew Moon's [ed25519-donna][1],
and is intended to be timing side-channel safe on [most architectures][2].

Compilation requires Go 1.12 or later due to required runtime library
functionality.

#### Features

 * Faster Ed25519 key generation, signing and verification.
 * Batch signature verification.
 * Faster X25519 key generation (`extra/x25519`).
 * Support for RFC 8032 Ed25519ph, Ed25519ctx.
 * Optional support for [ZIP-215][3] verification semantics.

#### Benchmarks

Comparisons between this package, `golang.org/x/crypto/ed25519`,
and `golang.org/x/crypto/curve25519`.  Numbers taken on a i7-10510U
CPU (@ 1.80GHz) with hyper-threading and Turbo Boost disabled.

```
benchmark                    old ns/op     new ns/op     delta
BenchmarkKeyGeneration-8     105543        34049         -67.74%
BenchmarkSigning-8           106769        35981         -66.30%
BenchmarkVerification-8      299258        140538        -53.04%

BenchmarkScalarBaseMult-8     80386         32649         -59.38% (X25519)
```

Batch verification on the same system takes approximately `5170515 ns`
to process a 64 signature batch using the `crypto/rand` entropy source
for roughly `80789 ns` per signature in the batch.

#### Verification semantics

As this is slightly different from upstream, and is a point of divergence
between many of the existing implementations, the verification semantics
are as follows, using terminology from [ed25519-speccheck][4]:

 * Both iterative and batch verification are cofactored.
 * Small order A is rejected by default (Unless ZIP-215 is enabled).
 * Small order R is rejected by default (Unless ZIP-215 is enabled).
 * A signature's scalar component must be in canonical form (S < L).
 * Non-canonical A is accepted (A is NOT reduced before hashing).
 * Non-canonical R is accepted (R is NOT reduced before hashing).

Note that subtle differences here can lead to issues in certain use cases,
in particular systems that require distributed consensus.  Historical
versions of this package used different semantics.

#### Notes

Most of the actual implementation is hidden in internal subpackages.
As far as reasonable, the implementation strives to be true to the
original, which results in a slightly un-idiomatic coding style, but
hopefully aids in auditability.

While there are other implementations that could have been used for the
base of this project, ed25519-donna was chosen due to its maturity and
the author's familiarity with the codebase.  The goal of this project
is not to be a general purpose library for doing various things with
this curve, and is more centered around "do common things reasonably
fast".

The following issues currently limit performance:

 * (All) The Go compiler's inliner gives up way too early, resulting
   in a lot of uneeded function call overhead.

 * (All 64 bit, except `amd64`, `arm64`, `ppc64`, `ppc64le`) Not enough
   of the `math/bits` calls have SSA intrinsic special cases.  For the
   64 bit codepath to be safe and performant both `bits.Add64` and
   `bits.Mul64` need to be constant time, and fast.

   See `go/src/cmd/compile/internal/gc/ssa.go`.

 * (All, except `amd64`) Key generation and signing performance will be
   hampered by the way `subtle.ConstantTimeCopy` is re-implemented for
   better performance.  This is easy to fix on a per-architecture basis.
   See `internal/ge25519/movecond_[slow,unsafe].go`.

 * (`amd64`) This could use a bigger table, AVX2, etc for even more
   performance.

While sanitizing sensitive values from memory is regarded as good practice,
Go as currently implemented and specified makes this impossible to do reliably
for several reasons:

 * The runtime can/will make copies of stack-allocated objects if the stack
   needs to be grown.

 * There is no `memset_s`/`explicit_bzero` equivalent provided by the runtime
   library (though Go up to and including 1.13.1 will not optimize out the
   existing sanitization code).

 * The runtime library's SHA-512 implementation's `Reset()` method does not
   actually clear the buffer, and calculating the digest via `Sum()` creates
   a copy of the buffer.

This implementation makes some attempts at sanitization, however this process
is fragile, and does not currently work in certain locations due to one or
more of the stated reasons.

#### TODO

 * Wait for the compiler to inline functions more intelligently.
 * Wait for the compiler to provide `math/bits` SSA special cases on
   more architectures.
 * Figure out solutions for speeding up the constant time table lookup
   on architectures where the fallback code path is used.

[1]: https://github.com/floodyberry/ed25519-donna
[2]: https://bearssl.org/ctmul.html
[3]: https://zips.z.cash/zip-0215
[4]: https://github.com/novifinancial/ed25519-speccheck

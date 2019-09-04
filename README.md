### ed25519 - Optimized ed25519 for Go

This package provides a drop-in replacement for `golang.org/x/crypto/ed25519`
with the aim to improve performance, primarily on systems with a low cost
`64 bit x 64 bit = 128 bit` multiply operation.

This implementation is derived from Andrew Moon's [ed25519-donna][1],
and is intended to be timing side-channel safe on [most architectures][2].

Compilation requires Go 1.12 or later due to required runtime library
functionality.

#### Features

 * Faster Ed25519 key generation, signing and verification.
 * Batch signature verification.
 * Faster X25519 key generation (`extra/x25519`).

#### Benchmarks

Comparisons between this package, `golang.org/x/crypto/ed25519`,
and `golang.org/x/crypto/curve25519`.  Numbers taken on a i7-8550U
CPU (@ 1.80GHz) with hyper-threading and Turbo Boost disabled.

```
benchmark                    old ns/op     new ns/op     delta
BenchmarkKeyGeneration-4     101526        45700         -54.99%
BenchmarkSigning-4           103660        47647         -54.04%
BenchmarkVerification-4      275115        163693        -40.50%

BenchmarkScalarBaseMult-4    80279         44429         -44.66%   (X25519)
```

Batch verification on the same system takes approximately `5082764 ns`
to process a 64 signature batch using the `crypto/rand` entropy source
for roughly `79418 ns` per signature in the batch.

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

 * (All, except `amd64`, `386`, `ppc64le`) Key generation and signing
   performance will be hampered by the use of `subtle.ConstantTimeCopy`.
   This is easy to fix on a per-architecture basis.  See
   `internal/ge25519/movecond_[slow,unsafe].go`.

 * (`amd64`) This could use a bigger table, AVX2, etc for even more
   performance.

#### TODO

 * Tons of review.
 * Wait for the compiler to inline functions more intelligently.
 * Wait for the compiler to provide `math/bits` SSA special cases on
   more architectures.
 * Figure out solutions for speeding up the constant time table lookup
   on architectures where the fallback code path is used.

[1]: https://github.com/floodyberry/ed25519-donna
[2]: https://bearssl.org/ctmul.html

# Pure-Go HashWX

A standard-library-only interpreter matching HashWX revision
`74b567a31276a4c5d7cb232a5b7639467f49f961` and Cap revision
`af624b9f15cb03f1f8194fb4c9f262ac34984923`. Source uses Go 1.21-compatible
language/library features. No Cgo, native compiler, JIT, Node, or WebAssembly
runtime is needed by the library.

## API

```go
p, err := hashwx.New(seed) // exactly 32 bytes; copied, not retained
if err != nil {
    return err
}
value := p.Hash(nonce) // uint64 input and output; safe to call concurrently
// Or: value, err := hashwx.Hash(seed, nonce)
```

`New` returns `ErrSeedSize` for every other seed length. All correctly sized
seeds can be generated in the pinned upstream algorithm; there is no HashX-like
program-rejection condition to emulate. The zero value of `Program` is invalid;
calling `Hash` on it or a nil pointer panics. Reuse a constructed program when
hashing multiple nonces with the same seed.

Every invocation has private registers and a 16,392-byte scratch area.
Arithmetic wraps at 64 bits, arithmetic shifts explicitly convert to `int64`,
and scratch reads/writes explicitly use little-endian encoding (including
unaligned loads crossing into the final R8 word).

This is the hash primitive, not the whole Cap challenge/token protocol. Cap's
challenge-to-seed SHA-256 derivation, target calculation, nonce parsing and
proof validation belong to its caller. HashWX is not a general-purpose digest
or password hash. This interpreter prioritizes portability and compatibility,
not the throughput of upstream native JIT backends.

## Tests

From this directory:

```sh
env GOCACHE=/tmp/samwaf-cap-gocache \
    GOMODCACHE=/tmp/samwaf-cap-gomodcache \
    go test -race -v .
```

The default tests include all four specification vectors, 1,024 checked-in
Node-oracle vectors (128 seeds, each with boundary and pseudorandom nonces),
invalid lengths, seed ownership, and concurrent use of one program. These run
without Node or access to an upstream checkout.

To also execute 512 fresh deterministic random seed/nonce differential cases,
set `HASHWX_CAP_ORACLE` to the absolute path of `core/src/hashwx.js` in the
pinned Cap checkout, with Node available in PATH:

```sh
env GOCACHE=/tmp/samwaf-cap-gocache \
    GOMODCACHE=/tmp/samwaf-cap-gomodcache \
    HASHWX_CAP_ORACLE=/path/to/pinned/cap/core/src/hashwx.js \
    go test -race -count=1 -v .
```

The live test skips when the oracle variable is absent; it fails (rather than
silently skipping) if an explicitly requested oracle cannot run. The optional
Node oracle uses Cap's WASM only inside the test process, never the Go library.
Regenerate fixtures with:

```sh
HASHWX_CAP_ORACLE=/path/to/pinned/cap/core/src/hashwx.js \
    node testdata/oracle.mjs --fixtures > testdata/cap-oracle.json
```

See [NOTICE.md](<NOTICE.md>) for copyright, source provenance, modifications and
LGPLv3 distribution considerations.

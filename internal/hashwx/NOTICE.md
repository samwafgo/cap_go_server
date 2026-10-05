# HashWX attribution and modification notice

This package is a modified, pure-Go adaptation of **HashWX**:

- Upstream: <https://github.com/tevador/hashwx>
- Exact source revision: `74b567a31276a4c5d7cb232a5b7639467f49f961`
- Copyright (c) 2020-2026 tevador <tevador@gmail.com>
- License: GNU Lesser General Public License version 3, as supplied by upstream.
  The complete upstream text is [LICENSE](<LICENSE>), and its incorporated GNU
  General Public License version 3 text is [COPYING](<COPYING>).
- Source references: upstream `src/program.c`, `src/program_exec.c`,
  `src/hashwx.c`, `src/siphash_rng.c`, `src/siphash_rng.h`, and
  `doc/specification.md` (including its four normative test vectors).

## Modifications (2026-10-05)

Ported program generation, lookup tables, SipHash-based random generation,
register initialization, memory write/read execution, and finalization to Go.
The fixed STORE/RMCG/arithmetic/BRANCH/HALT layout is represented by eight
arithmetic instructions per program; STORE, branches, and HALT are expressed
in structured Go loops. No algorithm, seed derivation, or hash output changes
are intended. Added seed-length validation, an immutable concurrent-safe API,
unit tests, deterministic differential fixtures, and an optional Node oracle
adapter. The Go adaptation in this directory is distributed under the same
LGPLv3 terms; it does not replace or alter the original upstream notices.

## Oracle provenance

Compatibility tests use Cap at revision
`af624b9f15cb03f1f8194fb4c9f262ac34984923`, specifically its
`core/src/hashwx.js` and the WASM interpreter it imports:
<https://github.com/tiagorangel1/cap/tree/af624b9f15cb03f1f8194fb4c9f262ac34984923>.
The test adapter is original glue that imports a separately supplied checkout;
no Cap JavaScript implementation or WASM binary is included in this package.
The JSON fixture contains only oracle inputs and outputs. Its generation is
reproducible using [the adapter](<testdata/oracle.mjs>) and the pinned checkout.

## Distribution considerations

Retain the upstream copyright, modification notice, and both license texts.
LGPLv3 requirements apply to conveying this library and combined binaries;
in particular, static Go linking does not remove corresponding-source and
recombination/relinking obligations. Merely including these license texts does
not by itself fulfill every obligation for a distributed combined work.
Review the supplied licenses for the intended release packaging.

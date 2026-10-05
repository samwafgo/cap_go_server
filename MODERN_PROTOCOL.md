# Embedded modern Cap protocol

The new `Engine` is a pure-Go implementation of **@cap.js/core 0.1.3**, pinned to
[tiagozip/cap commit af624b9f15cb03f1f8194fb4c9f262ac34984923](https://github.com/tiagozip/cap/tree/af624b9f15cb03f1f8194fb4c9f262ac34984923).
Protocol sources: `core/src/index.js`, `crypto.js`, `prng.js`, `rsw.js`,
`hashwx.js`, `instrumentation.js`, and `detect.js`.

These are modified/translated implementations, not unmodified upstream files.
Upstream copyright: **Copyright 2025 Tiago**, Apache-2.0; the complete original
license and attribution are preserved in `MODERN_LICENSE`. The old `cap.go`
API and its license remain intact. HashWX has **separate LGPLv3 obligations**;
see the license/attribution in `internal/hashwx` before binary distribution.

## Stable embedding API

```go
engine, err := capserver.NewEngine(capserver.EngineConfig{
    Secret: secret, // >=16 bytes; use 32+ random bytes in production
    Store: persistentAtomicStore, // nil = bounded process-local memory
    TokenTTL: 20 * time.Minute,
    ChallengeTTL: 10 * time.Minute,
    RSWKey: persistedKeypair, // optional; default lazily generates 2048 bits
    MemoryCapacity: 10000,
})
challenge, err := engine.GenerateChallenge(ctx, trustedScope, capserver.Options{
    Format: 2,
    Protocols: []string{"sha256-pow", "rsw", "hashwx", "instrumentation"},
    DynamicEscalation: true, // opt-in risk-driven difficulty escalation
    InstrumentationOptions: capserver.InstrumentationOptions{
        BlockAutomatedBrowsers: true,
        CheckCount: 18, // 0 = default: 18 when blocking, else 8; 1..18 explicit
        // ScopeSeed is derived by the Engine (HMAC of secret+scope);
        // set it only from trusted input, never from request data
    },
})
result, err := engine.Redeem(ctx, trustedScope, rawJSONBody)
valid, err := engine.ValidateToken(ctx, trustedScope, result.Token)
```

`ModernChallenge` and `ModernRedeem` marshal to the upstream browser wire shape.
Failed proofs return `Success:false` with `Reason`. Operational failures return
an error and never authorize; some also return a failure result. Check `err`
before dereferencing a result. `ModernRedeem` does not expose upstream's private
`tokenKey` because the Engine stores token verification records itself.

Host code **must derive scope from trusted host + policy + client IP**, not from
request JSON or unchecked forwarded headers. Scope is required (1..4096 bytes),
stored as JWT `sk`, and included in store keys. Different scopes and secrets
cannot share challenge/token authorization even when using one Store.

## Protocol coverage

- Format 1: compact `{c,s,d}` challenge and HS256 JWT; FNV1a/xorshift32 PRNG
  derives salt/target from JWT + 1-based challenge index. SHA256 prefix matching
  includes odd-nibble difficulty. Optional instrumentation uses encrypted `ei`.
- Format 2: arbitrary ordered mixing (including repeated protocol entries) of
  `sha256-pow`, `rsw`, `hashwx`, `instrumentation`. Empty protocols defaults to
  `rsw`, as upstream does. Set instrumentation explicitly in `Protocols`;
  `Options.Instrumentation` enables it for **format 1 only**.
- AES-256-GCM keys are HMAC-SHA256(secret, info), using `cap:enc-v1` and
  `cap:fmt2-v1`. Wire layout is base64url(12-byte IV || 16-byte tag || ciphertext).
- JWT `exp` and `iat`, challenge `expires`, token `expires` are **milliseconds**,
  not RFC7519 seconds. Do not validate these with a seconds-based JWT library.
- HashWX derives the 32-byte seed as SHA256(challenge[32] || block uint64-LE),
  then verifies the pure-Go program result against floor(UINT64_MAX/difficulty).
- RSW uses 2048-bit modulus, two distinct 1024-bit primes, math/big CRT trapdoor
  precomputation, random 256-bit mint exponent, and fixed 512-digit wire hex.
  Mint parameters are immutable/concurrency-safe. Up to 32 t-specific minters
  are cached. Default t=75000; allowed t=1..10000000. `GenerateRSWKeypair()`
  returns decimal-string `{N,p,q,bits}` compatible with upstream serialization.
  Persist the **secret** factors securely to reuse a key after restart; they
  never appear in public challenges. Key factors/product/primality are checked.
- Instrumentation uses the independent `internal/instrumentation` generator and
  verifier. Engine preserves blocked/timeout handling, failure reasons,
  `blockedBy`, and `riskFlags`. Metadata is authenticated and expires with its
  challenge. For exact generator/obfuscation feature coverage consult that
  package: the Engine propagates unsupported-feature errors, never omits it.
- Instrumentation **always injects automated-browser checks**, including when
  `BlockAutomatedBrowsers` is false (observation mode). `CheckCount` selects how
  many of the 18 available checks are injected: 0 means "default" — all 18 when
  blocking, the upstream default sample of 8 in observation mode — explicit
  values must be 1..18 (out of range is rejected, never silently clamped).
  `BlockAutomatedBrowsers` reaches only the metadata and controls what a hit
  means at redemption (see the next two sections); it no longer controls
  injection. The default obfuscation level follows the mode: **6 when
  blocking, 3 otherwise**; an explicit 1..10 always wins.
- Instrumentation check selection is **deterministic per scope through the
  Engine**: the Engine derives `ScopeSeed` as the first 32 hex characters of
  `HMAC-SHA256(secret, "cap:instr-sel:"+scope)` and passes it (plus
  `CheckCount`) to the generator, so one client cannot re-roll a challenge
  hoping for an easier check sample. A host-supplied non-empty `ScopeSeed`
  wins over the derivation (use only trusted input); an empty seed keeps the
  per-challenge random shuffle for direct generator callers. Determinism
  applies only to which checks are injected: variable names, initial values,
  arithmetic, and salts stay per-challenge random, and a smaller `CheckCount`
  is a prefix of the same permutation.

No Node, Bun, Cgo, WASM interpreter, child process, network call, or third-party
Go dependency is used by the production Engine. Browser JavaScript execution
remains a client-side responsibility.

## Observation mode: checks versus blocking

`BlockAutomatedBrowsers=false` is **observation mode**: instrumentation still
injects the default 8-check sample, and the client-side script still
self-reports `blocked:true` when one fires, but the redemption **succeeds**
with the risk flag `instr_blocked_reported` instead of failing. The host
sees the hit in `RiskFlags` (and in escalation, below) without turning the
visitor away. `BlockAutomatedBrowsers=true` keeps the hard failure
`instr_automated_browser` for a client-reported hit.

Server-side `Detect` evaluation is unchanged: whenever the probe is present
it runs, and its verdict always lands in `RiskFlags`/`BlockedBy`. In
observation mode a failing verdict does not gate the redemption (the probe is
client-supplied); in blocking mode it fails with `instr_automated_browser`,
and a missing probe fails with `instr_probe_missing`.

Honest boundary: the checks and the probe are **client-side and
client-reported**. A sufficiently capable automation stack can patch the
browser environment the checks observe, or simply not report the hit, and
redeem with no risk flags. Observation mode is visibility, not a proof.

## Risk-driven dynamic escalation (`DynamicEscalation`)

`Options.DynamicEscalation` (zero value **false**: no counter reads or
writes, byte-for-byte the previous behavior) opts a challenge's scope into
difficulty escalation:

- **Triggers.** When a redemption fails with reason `instr_automated_browser`,
  or succeeds with non-empty `RiskFlags` (including `instr_blocked_reported`
  and `Detect` risk flags such as `native_tamper`), the Engine increments a
  scope-level counter in the injected `Store`. Only challenges generated
  with `DynamicEscalation` write: the flag is carried inside the **signed**
  JWT claims (`de`), so a client cannot forge or strip it, and a
  `DynamicEscalation=false` challenge never triggers. A failed blocked
  redemption does not consume its challenge, so repeated attempts keep
  incrementing.
- **Counter semantics.** The counter is a decimal string (stored value bounded
  at 1,000,000; the effective level caps at 4 long before that) under the
  engine store-key namespace (`kind=escalate`, namespaced by secret and
  scope). It lives under a **24h sliding TTL** refreshed by every trigger;
  after 24h without a trigger it expires and the scope starts again at level
  0. The increment is a non-atomic read-modify-write: concurrent triggers
  for one scope may undercount (worst case escalation arrives one trigger
  late). The counter is advisory — Store read/write failures are swallowed
  and never fail a redemption or a challenge generation; a corrupt value
  reads as level 0.
- **Effect.** `GenerateChallenge` reads the counter, takes
  `level=min(count,4)`, and raises only the knobs the caller **explicitly
  configured** for the protocols that challenge **actually uses**:

  | knob | escalation | hard cap (= validation max) |
  |---|---|---|
  | `ChallengeDifficulty` (sha256-pow in use) | `+level` | 16 |
  | `ChallengeCount` (sha256-pow in use) | `+2*level` | 1000 |
  | `HashWXDifficulty` (hashwx in use) | `<<level` | 1000000000 |
  | `RSWT` (rsw in use) | `<<level` | 10000000 |
  | `InstrumentationOptions.ObfuscationLevel` (instrumentation in use) | `+level` | 10 |

  Zero ("use the default") values and components not in use are never
  touched, values already outside the validation bounds are never rescued
  into validity, and the caps equal the library's existing validation
  maxima, so escalated values always pass the normal option validation.
  Hosts that rely on defaults see no escalation: set the knobs explicitly
  (the SamWaf configuration layer fills every knob and enables this by
  default there).

Honest boundaries: escalation only punishes **scopes that were already
detected** (a blocked report, or risk-flagged probes); a client that forges
its entire environment and reports no risk flags never escalates its scope.
Escalation is per scope, so a bot farm rotating clients/keys distributes the
cost as before. The counter is advisory, not a security control: store
failures or the tolerated undercount can delay escalation, never endanger
authorization.

## Store and security contract

```go
type Store interface {
    Put(context.Context, string, []byte, time.Time) error
    PutIfAbsent(context.Context, string, []byte, time.Time) (bool, error)
    Get(context.Context, string) ([]byte, bool, error)
    Take(context.Context, string) ([]byte, bool, error)
}
```

Expiration arguments are absolute times. Reads treat expired/missing values as
`nil,false,nil` and return owned byte slices. `PutIfAbsent` and `Take` MUST be
atomic across the entire cluster. Redis implementations should use SET NX with
absolute expiration and GETDEL (or equivalent atomic Lua). All persistence
errors fail closed. Store backends must **not evict live replay markers** when
full. Choose non-evicting Redis policy / dedicated capacity accordingly.

The nonce is claimed atomically only **after all proofs, scope, and expiration
validate**, keyed by authenticated JWT signature. Its lifetime equals challenge
expiration. Failed proofs cannot burn a challenge. The successful redemption
creates an upstream-shaped random `16hex:30hex` verification token. Only its
HMAC-derived lookup key is stored, never the raw token. Validation atomically
`Take`s it, so by default it is **one use**, even with concurrent requests.
An incorrect scope cannot burn a valid token. If token storage fails after the
nonce claim, the nonce stays consumed; clients must request a new challenge.
There is intentionally no insecure stateless / keep-token / no-replay mode.

`NewMemoryStore(capacity)` has a default limit of 10000 entries, mutex-protected
atomic operations, expiry cleanup on every write, per-key cleanup on reads, and
explicit `Cleanup() int`. No janitor goroutine needs lifecycle management.
At capacity it returns `ErrStoreFull`, never evicts live entries. A process-local
store is not durable: restarting it loses replay markers. For restart/multi-node
safety the host must inject a shared persistent Store with durable writes and
retain the same secret. A reused RSW key alone does not supply replay durability.

## Deliberately stricter input boundaries

- Submission body <=2 MiB, signed JWT <=1 MiB; scope <=4096 bytes.
- TTL is positive and <=24h. Expiry equality is expired. Future `iat` is rejected;
  synchronize clocks across cluster instances.
- Format-1 nonce is a nonnegative decimal JSON integer <=2^53-1. Format-2 nonce
  may additionally be a 1..20-digit string <=2^64-1; leading zeroes are preserved
  for SHA256 strings. Fractions, exponent notation, negatives, arbitrary strings,
  JSON floats that lose JS precision, and oversized numbers are rejected.
  These narrow upstream's overly permissive SHA nonce input, not browser output.
- JWT header must be canonical upstream HS256/typ JWT; base64url is strict and
  signatures compare in constant time. Unknown formats/protocols are rejected.
- RSW solution is <=512 hex digits (optional lowercase `0x`), with strict hex,
  uppercase digits and omitted leading zeroes accepted; comparison is constant
  time after fixed-size normalization.
- Upstream c/s/d and HashWX range limits are enforced. A protocol list has at most
  16 entries and at most 1100 resulting challenges to bound amplification.
- `Extra` must JSON-marshal and fit the JWT cap; it grants no authorization.

These APIs do not themselves rate-limit requests; apply host-side rate limits
and HTTP body limits before invoking cryptographic verification.

## Tests and differential oracle

```sh
GOCACHE=/tmp/samwaf-cap-gocache GOMODCACHE=/tmp/samwaf-cap-gomodcache go test ./...
GOCACHE=/tmp/samwaf-cap-gocache GOMODCACHE=/tmp/samwaf-cap-gomodcache go test -race ./...
```

`TestModernNodeOracleBidirectional` uses **Node 25** and the pinned upstream
source directly (no npm install) as a development-only oracle. It tests Go →
Node and Node → Go generation/verification for format 1 and format 2 mixed with
all four protocols, plus an **escalated** variant (risk counter pre-seeded, so
difficulty/count/T/obfuscation are raised and the signed `de` claim is present)
to prove escalated challenges stay upstream-solvable. RSW is solved in Node with
repeated squaring; HashWX uses upstream WASM only in the **oracle test process**,
never in production Go. Instrumentation metadata/results are cross-validated;
execution of generated browser instrumentation is tested separately in its own
package, including observation-mode injection, `CheckCount`/`ScopeSeed`
selection determinism, the 6/3 obfuscation default, escalation triggers/caps/
TTL/race tolerance, and the observation-mode `instr_blocked_reported` flag.

Set `CAP_UPSTREAM_SRC=/path/to/pinned/core/src` to run the oracle elsewhere
(default `/tmp/cap-oracle-src/core/src`). `internal/hashwx` keeps its own
optional live differential oracle: set `HASHWX_CAP_ORACLE` to the **path of the
pinned `core/src/hashwx.js`** (not a flag). Real-Chrome execution of generated
instrumentation at every obfuscation level runs in
`internal/instrumentation` with `CAP_BROWSER_TEST=1` (needs
`google-chrome`; covers a genuine-browser validation path and a full
18-check injection detection path). Each test skips when its oracle is
unavailable, so a generic `go test` pass alone is not evidence that the oracles
ran. Security tests cover atomic replay/token races, scope isolation,
malformed/expired input, failed proofs preserving nonce, failures after nonce
commit, shared-store restart, store capacity/copies/expiry/cancellation, and
trapdoor-vs-sequential RSW.

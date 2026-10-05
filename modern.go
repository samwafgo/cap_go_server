// Modified pure-Go protocol port of @cap.js/core 0.1.3.
// Upstream Copyright 2025 Tiago, Apache-2.0; see MODERN_LICENSE.
package capserver

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/samwafgo/cap_go_server/internal/hashwx"
	"github.com/samwafgo/cap_go_server/internal/instrumentation"
)

// InstrumentationOptions configures the embedded, pure-Go JS generator.
type InstrumentationOptions = instrumentation.Options

// EngineConfig must use the same high-entropy secret and durable Store on all
// instances. Nil Store selects a bounded local store (not cluster persistence).
type EngineConfig struct {
	Secret         []byte
	Store          Store
	TokenTTL       time.Duration
	ChallengeTTL   time.Duration
	RSWKey         *RSWKeypair
	MemoryCapacity int
}
type Options struct {
	Format                 int                    `json:"format,omitempty"`
	Protocols              []string               `json:"protocols,omitempty"`
	ChallengeCount         int                    `json:"challengeCount,omitempty"`
	ChallengeSize          int                    `json:"challengeSize,omitempty"`
	ChallengeDifficulty    int                    `json:"challengeDifficulty,omitempty"`
	ExpiresMs              int64                  `json:"expiresMs,omitempty"`
	HashWXDifficulty       int                    `json:"hashwxDifficulty,omitempty"`
	HashWXNoncesPerHash    int                    `json:"hashwxNoncesPerHash,omitempty"`
	HashWXChallengeCount   int                    `json:"hashwxChallengeCount,omitempty"`
	RSWT                   int                    `json:"t,omitempty"`
	Instrumentation        bool                   `json:"instrumentation,omitempty"`
	InstrumentationOptions InstrumentationOptions `json:"instrumentationOptions,omitempty"`
	Extra                  map[string]any         `json:"extra,omitempty"`
	// DynamicEscalation enables risk-driven difficulty escalation for this
	// scope. When true, GenerateChallenge reads the scope's risk counter from
	// the Store and raises the explicitly configured difficulty knobs of the
	// protocols this challenge actually uses (never zero/"use the default"
	// values, never components that are not in use), and signs the escalation
	// flag into the challenge claims so Redeem can record triggers: a failed
	// redemption with reason instr_automated_browser, or a successful
	// redemption with non-empty RiskFlags, increments the counter under a 24h
	// sliding TTL. The zero value (false) reads and writes no counter at all
	// and behaves exactly like before; the embedding host decides its default.
	DynamicEscalation bool `json:"dynamicEscalation,omitempty"`
}
type ModernParameters struct {
	C int `json:"c"`
	S int `json:"s"`
	D int `json:"d"`
}
type ModernProtocolChallenge struct {
	Protocol string `json:"protocol"`
	Payload  any    `json:"payload"`
}
type ModernChallenge struct {
	Challenge       *ModernParameters         `json:"challenge,omitempty"`
	Token           string                    `json:"token"`
	Expires         int64                     `json:"expires"`
	Format          int                       `json:"format,omitempty"`
	Challenges      []ModernProtocolChallenge `json:"challenges,omitempty"`
	Instrumentation string                    `json:"instrumentation,omitempty"`
}
type ModernRedeem struct {
	Success    bool     `json:"success"`
	Reason     string   `json:"reason,omitempty"`
	Token      string   `json:"token,omitempty"`
	Expires    int64    `json:"expires,omitempty"`
	Scope      string   `json:"scope,omitempty"`
	Iat        int64    `json:"iat,omitempty"`
	RiskFlags  []string `json:"riskFlags,omitempty"`
	InstrError bool     `json:"instr_error,omitempty"`
	BlockedBy  []string `json:"blockedBy,omitempty"`
}
type Engine struct {
	secret                 []byte
	store                  Store
	tokenTTL, challengeTTL time.Duration
	rswMu                  sync.Mutex
	rswN, rswP, rswQ       *big.Int
	minters                map[int]*rswMinter
}
type modernClaims struct {
	F     int            `json:"f,omitempty"`
	N     string         `json:"n"`
	C     int            `json:"c,omitempty"`
	S     int            `json:"s,omitempty"`
	D     int            `json:"d,omitempty"`
	Exp   int64          `json:"exp"`
	Iat   int64          `json:"iat"`
	Scope string         `json:"sk"`
	EI    string         `json:"ei,omitempty"`
	EV    string         `json:"ev,omitempty"`
	X     map[string]any `json:"x,omitempty"`
	// DE records that this challenge was generated with DynamicEscalation, so
	// Redeem records risk triggers for its scope. It is inside the signed
	// token: a client cannot forge or strip it.
	DE bool `json:"de,omitempty"`
}
type modernExpected struct {
	Protocol  string                    `json:"protocol"`
	Salt      string                    `json:"salt,omitempty"`
	Target    string                    `json:"target,omitempty"`
	Y         string                    `json:"y,omitempty"`
	C         string                    `json:"c,omitempty"`
	D         int                       `json:"d,omitempty"`
	N         int                       `json:"n,omitempty"`
	InstrMeta *instrumentation.Metadata `json:"instrMeta,omitempty"`
}
type modernExpectedEnvelope struct {
	Expected []modernExpected `json:"expected"`
}
type modernSubmission struct {
	Token     string            `json:"token"`
	Solutions []json.RawMessage `json:"solutions"`
	Instr     json.RawMessage   `json:"instr"`
	Blocked   bool              `json:"instr_blocked"`
	Timeout   bool              `json:"instr_timeout"`
}
type modernSolution struct {
	Nonce   json.RawMessage `json:"nonce"`
	Y       string          `json:"y"`
	Instr   json.RawMessage `json:"instr"`
	Blocked bool            `json:"blocked"`
	Timeout bool            `json:"timeout"`
}

const maxModernBody = 2 * 1024 * 1024
const maxModernTTL = 24 * time.Hour

func NewEngine(c EngineConfig) (*Engine, error) {
	if len(c.Secret) < 16 {
		return nil, errors.New("cap: secret must be at least 16 bytes")
	}
	if c.TokenTTL == 0 {
		c.TokenTTL = 20 * time.Minute
	}
	if c.ChallengeTTL == 0 {
		c.ChallengeTTL = 10 * time.Minute
	}
	if c.TokenTTL < time.Millisecond || c.TokenTTL > maxModernTTL || c.ChallengeTTL < time.Millisecond || c.ChallengeTTL > maxModernTTL {
		return nil, ErrInvalidOptions
	}
	if c.Store == nil {
		c.Store = NewMemoryStore(c.MemoryCapacity)
	}
	e := &Engine{secret: append([]byte(nil), c.Secret...), store: c.Store, tokenTTL: c.TokenTTL, challengeTTL: c.ChallengeTTL, minters: make(map[int]*rswMinter)}
	if c.RSWKey != nil {
		var err error
		e.rswN, e.rswP, e.rswQ, err = parseRSWKey(c.RSWKey)
		if err != nil {
			return nil, err
		}
	}
	return e, nil
}
func validModernScope(scope string) bool { return len(scope) > 0 && len(scope) <= 4096 }
func normalizeModernOptions(o Options) (Options, error) {
	if o.Format == 0 {
		o.Format = 1
	}
	if o.Format != 1 && o.Format != 2 {
		return o, ErrInvalidOptions
	}
	if o.ChallengeCount == 0 {
		o.ChallengeCount = 50
	}
	if o.ChallengeSize == 0 {
		o.ChallengeSize = 32
	}
	if o.ChallengeDifficulty == 0 {
		o.ChallengeDifficulty = 4
	}
	if o.ChallengeCount < 1 || o.ChallengeCount > 1000 || o.ChallengeSize < 1 || o.ChallengeSize > 256 || o.ChallengeDifficulty < 1 || o.ChallengeDifficulty > 16 {
		return o, ErrInvalidOptions
	}
	if o.HashWXDifficulty == 0 {
		o.HashWXDifficulty = 1000000
	}
	if o.HashWXNoncesPerHash == 0 {
		o.HashWXNoncesPerHash = 65536
	}
	if o.HashWXChallengeCount == 0 {
		o.HashWXChallengeCount = 4
	}
	if o.HashWXDifficulty < 1 || o.HashWXDifficulty > 1000000000 || o.HashWXNoncesPerHash < 1 || o.HashWXNoncesPerHash > 1048576 || o.HashWXChallengeCount < 1 || o.HashWXChallengeCount > 64 {
		return o, ErrInvalidOptions
	}
	if o.RSWT == 0 {
		o.RSWT = 75000
	}
	if o.RSWT < 1 || o.RSWT > 10000000 || len(o.Protocols) > 16 {
		return o, ErrInvalidOptions
	}
	if o.ExpiresMs < 0 || o.ExpiresMs > maxModernTTL.Milliseconds() {
		return o, ErrInvalidOptions
	}
	if o.Format == 2 && len(o.Protocols) == 0 {
		o.Protocols = []string{"rsw"}
	}
	if o.Format == 1 && len(o.Protocols) > 0 {
		return o, errors.New("cap: protocols require format 2")
	}
	count := 0
	for _, p := range o.Protocols {
		switch p {
		case "sha256-pow":
			count += o.ChallengeCount
		case "hashwx":
			count += o.HashWXChallengeCount
		case "rsw", "instrumentation":
			count++
		default:
			return o, fmt.Errorf("cap: unsupported protocol %q", p)
		}
	}
	if count > 1100 {
		return o, ErrInvalidOptions
	}
	return o, nil
}
func (e *Engine) rsw(t int) (*rswMinter, error) {
	e.rswMu.Lock()
	defer e.rswMu.Unlock()
	if m := e.minters[t]; m != nil {
		return m, nil
	}
	if e.rswN == nil {
		k, err := GenerateRSWKeypair()
		if err != nil {
			return nil, err
		}
		e.rswN, e.rswP, e.rswQ, err = parseRSWKey(k)
		if err != nil {
			return nil, err
		}
	}
	m, err := newRSWMinterParsed(e.rswN, e.rswP, e.rswQ, t)
	if err == nil && len(e.minters) < 32 {
		e.minters[t] = m
	}
	return m, err
}

// GenerateChallenge binds the challenge to a trusted host/policy/client scope.
// Scope must be derived by the host, never copied from untrusted request JSON.
func (e *Engine) GenerateChallenge(ctx context.Context, scope string, opts Options) (*ModernChallenge, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validModernScope(scope) {
		return nil, ErrInvalidScope
	}
	if opts.DynamicEscalation {
		// Advisory: a missing, expired or unreadable counter escalates nothing.
		if level := e.escalationLevel(ctx, scope); level > 0 {
			escalateOptions(&opts, level)
		}
	}
	o, err := normalizeModernOptions(opts)
	if err != nil {
		return nil, err
	}
	if o.InstrumentationOptions.ScopeSeed == "" {
		// Derive a per-scope selection seed so one client always faces the
		// same instrumentation checks. A host-supplied seed wins.
		o.InstrumentationOptions.ScopeSeed = e.instrScopeSeed(scope)
	}
	ttl := e.challengeTTL
	if o.ExpiresMs != 0 {
		ttl = time.Duration(o.ExpiresMs) * time.Millisecond
	}
	now := time.Now().UnixMilli()
	exp := now + ttl.Milliseconds()
	claims := modernClaims{Iat: now, Exp: exp, Scope: scope, X: o.Extra, DE: o.DynamicEscalation}
	out := &ModernChallenge{Expires: exp}
	if o.Format == 1 {
		claims.N, err = modernRandomHex(25)
		if err != nil {
			return nil, err
		}
		claims.C = o.ChallengeCount
		claims.S = o.ChallengeSize
		claims.D = o.ChallengeDifficulty
		out.Challenge = &ModernParameters{claims.C, claims.S, claims.D}
		if o.Instrumentation {
			blob, meta, xerr := instrumentation.Generate(o.InstrumentationOptions, nil)
			if xerr != nil {
				return nil, xerr
			}
			meta.Expires = exp
			claims.EI, err = modernEncrypt(meta, e.secret, "cap:enc-v1")
			if err != nil {
				return nil, err
			}
			out.Instrumentation = blob
		}
	} else {
		claims.F = 2
		claims.N, err = modernRandomHex(16)
		if err != nil {
			return nil, err
		}
		out.Format = 2
		expected := modernExpectedEnvelope{}
		for _, proto := range o.Protocols {
			if err = ctx.Err(); err != nil {
				return nil, err
			}
			switch proto {
			case "sha256-pow":
				for i := 0; i < o.ChallengeCount; i++ {
					salt, xerr := modernRandomHex(o.ChallengeSize)
					if xerr != nil {
						return nil, xerr
					}
					target := strings.Repeat("0", o.ChallengeDifficulty)
					out.Challenges = append(out.Challenges, ModernProtocolChallenge{proto, map[string]any{"salt": salt, "target": target}})
					expected.Expected = append(expected.Expected, modernExpected{Protocol: proto, Salt: salt, Target: target})
				}
			case "hashwx":
				d := int(math.Floor(float64(o.HashWXDifficulty)/float64(o.HashWXChallengeCount) + 0.5))
				if d < 1 {
					d = 1
				}
				for i := 0; i < o.HashWXChallengeCount; i++ {
					c, xerr := modernRandomHex(32)
					if xerr != nil {
						return nil, xerr
					}
					out.Challenges = append(out.Challenges, ModernProtocolChallenge{proto, map[string]any{"c": c, "d": d, "n": o.HashWXNoncesPerHash}})
					expected.Expected = append(expected.Expected, modernExpected{Protocol: proto, C: c, D: d, N: o.HashWXNoncesPerHash})
				}
			case "rsw":
				m, xerr := e.rsw(o.RSWT)
				if xerr != nil {
					return nil, xerr
				}
				x, y, xerr := m.mint()
				if xerr != nil {
					return nil, xerr
				}
				out.Challenges = append(out.Challenges, ModernProtocolChallenge{proto, map[string]any{"N": m.nhex, "x": x, "t": m.t}})
				expected.Expected = append(expected.Expected, modernExpected{Protocol: proto, Y: y})
			case "instrumentation":
				blob, meta, xerr := instrumentation.Generate(o.InstrumentationOptions, nil)
				if xerr != nil {
					return nil, xerr
				}
				meta.Expires = exp
				out.Challenges = append(out.Challenges, ModernProtocolChallenge{proto, map[string]any{"blob": blob}})
				expected.Expected = append(expected.Expected, modernExpected{Protocol: proto, InstrMeta: &meta})
			}
		}
		claims.EV, err = modernEncrypt(expected, e.secret, "cap:fmt2-v1")
		if err != nil {
			return nil, err
		}
	}
	out.Token, err = modernSign(claims, e.secret)
	if err != nil {
		return nil, err
	}
	if len(out.Token) > maxModernBody/2 {
		return nil, ErrInvalidOptions
	}
	return out, nil
}

// instrScopeSeed derives the deterministic instrumentation check-selection
// seed for a scope: the first 32 hex characters of
// HMAC-SHA256(secret, "cap:instr-sel:"+scope). Hosts never see this value; it
// only keys the check-sample permutation so one scope always faces the same
// checks while names, values, arithmetic and salts stay random.
func (e *Engine) instrScopeSeed(scope string) string {
	mac := hmac.New(sha256.New, e.secret)
	mac.Write([]byte("cap:instr-sel:" + scope))
	return hex.EncodeToString(mac.Sum(nil))[:32]
}

const (
	escalationKind       = "escalate"
	escalationTTL        = 24 * time.Hour
	escalationMaxLevel   = 4
	escalationMaxCounter = 1000000
)

func (e *Engine) escalationStoreKey(scope string) string {
	return e.storeKey(escalationKind, scope, "v1")
}

// escalationLevel returns min(counter, 4) for the scope, 0 when there is no
// counter, it expired, it is corrupt, or the Store read fails. The counter is
// advisory: read failures never fail challenge generation, they merely
// escalate nothing.
func (e *Engine) escalationLevel(ctx context.Context, scope string) int {
	v, ok, err := e.store.Get(ctx, e.escalationStoreKey(scope))
	if err != nil || !ok {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(v)))
	if err != nil || n < 1 {
		return 0
	}
	if n > escalationMaxLevel {
		return escalationMaxLevel
	}
	return n
}

// bumpEscalation increments the scope's risk counter and refreshes a 24h
// sliding TTL from this trigger. The read-modify-write is not atomic, so
// concurrent triggers for the same scope can undercount (worst case the
// escalation arrives one trigger late); the counter is advisory, so Store
// errors are tolerated and never surfaced to the caller.
func (e *Engine) bumpEscalation(ctx context.Context, scope string) {
	if !validModernScope(scope) {
		return
	}
	key := e.escalationStoreKey(scope)
	n := 0
	if v, ok, err := e.store.Get(ctx, key); err != nil {
		return // advisory: a failed read skips this increment
	} else if ok {
		if m, perr := strconv.Atoi(strings.TrimSpace(string(v))); perr == nil && m > 0 {
			n = m
		}
	}
	if n < escalationMaxCounter {
		n++
	}
	if err := e.store.Put(ctx, key, []byte(strconv.Itoa(n)), time.Now().Add(escalationTTL)); err != nil {
		return // advisory: a failed write skips this increment
	}
}

// noteInstrFailure records an instr_automated_browser redemption failure as an
// escalation trigger, but only for challenges generated with
// DynamicEscalation (claims are signed, so the flag is trusted).
func (e *Engine) noteInstrFailure(ctx context.Context, c *modernClaims, f *ModernRedeem) {
	if f == nil || !c.DE || f.Reason != "instr_automated_browser" {
		return
	}
	e.bumpEscalation(ctx, c.Scope)
}

// escalateOptions raises the difficulty knobs that the caller explicitly
// configured for the protocols this challenge actually uses. Zero values mean
// "use the default" and are never touched, components that are not in use for
// the challenge format are never touched, and only values already inside the
// library's validation bounds are raised, so escalation can never rescue an
// invalid configuration. Hard caps equal the existing validation maxima, so
// escalated values always pass normalizeModernOptions unchanged.
func escalateOptions(o *Options, level int) {
	if level < 1 {
		return
	}
	shaInUse := o.Format != 2 // format 0/1 always selects the sha256 protocol
	hashwxInUse, rswInUse, instrInUse := false, false, o.Instrumentation
	if o.Format == 2 {
		protocols := o.Protocols
		if len(protocols) == 0 {
			protocols = []string{"rsw"} // matches normalizeModernOptions
		}
		for _, p := range protocols {
			switch p {
			case "sha256-pow":
				shaInUse = true
			case "hashwx":
				hashwxInUse = true
			case "rsw":
				rswInUse = true
			case "instrumentation":
				instrInUse = true
			}
		}
	}
	if shaInUse {
		if o.ChallengeDifficulty >= 1 && o.ChallengeDifficulty <= 16 {
			o.ChallengeDifficulty = min(o.ChallengeDifficulty+level, 16)
		}
		if o.ChallengeCount >= 1 && o.ChallengeCount <= 1000 {
			o.ChallengeCount = min(o.ChallengeCount+2*level, 1000)
		}
	}
	if hashwxInUse && o.HashWXDifficulty >= 1 && o.HashWXDifficulty <= 1000000000 {
		o.HashWXDifficulty = min(o.HashWXDifficulty<<uint(level), 1000000000)
	}
	if rswInUse && o.RSWT >= 1 && o.RSWT <= 10000000 {
		o.RSWT = min(o.RSWT<<uint(level), 10000000)
	}
	if instrInUse && o.InstrumentationOptions.ObfuscationLevel >= 1 && o.InstrumentationOptions.ObfuscationLevel <= 10 {
		o.InstrumentationOptions.ObfuscationLevel = min(o.InstrumentationOptions.ObfuscationLevel+level, 10)
	}
}

func modernFailure(reason string) *ModernRedeem { return &ModernRedeem{Reason: reason} }
func modernInstr(meta *instrumentation.Metadata, instr json.RawMessage, blocked, timeout bool) (*ModernRedeem, []string, error) {
	fail := func(s string) *ModernRedeem { return &ModernRedeem{Reason: s, InstrError: true} }
	if meta == nil {
		return fail("instr_corrupted"), nil, nil
	}
	if meta.Expires != 0 && time.Now().UnixMilli() >= meta.Expires {
		return fail("instr_expired"), nil, nil
	}
	if blocked {
		if meta.BlockAutomatedBrowsers {
			return fail("instr_automated_browser"), nil, nil
		}
		// Observation mode: the client self-reported an automated-browser hit
		// in the injected checks. The redemption still succeeds, but the
		// risk flag makes the hit visible (and escalation-eligible) to the host.
		return nil, []string{"instr_blocked_reported"}, nil
	}
	if timeout {
		return fail("instr_timeout"), nil, nil
	}
	if len(instr) == 0 || string(instr) == "null" {
		return fail("instr_missing"), nil, nil
	}
	r, err := instrumentation.Validate(*meta, instr)
	if err != nil {
		return fail("instr_failed"), nil, err
	}
	if !r.Success {
		f := fail(r.Reason)
		if f.Reason == "" {
			f.Reason = "instr_failed"
		}
		f.BlockedBy = r.BlockedBy
		return f, nil, nil
	}
	return nil, r.RiskFlags, nil
}
func verifyModernHashWX(ex modernExpected, nonce json.RawMessage) bool {
	_, n, ok := parseModernNonce(nonce, true)
	if !ok || ex.D < 1 || ex.D > 1000000000 || ex.N < 1 || ex.N > 1048576 || len(ex.C) != 64 {
		return false
	}
	c, err := hex.DecodeString(ex.C)
	if err != nil {
		return false
	}
	buf := make([]byte, 40)
	copy(buf, c)
	binary.LittleEndian.PutUint64(buf[32:], n/uint64(ex.N))
	seed := sha256.Sum256(buf)
	p, err := hashwx.New(seed[:])
	if err != nil {
		return false
	}
	return p.Hash(n) <= math.MaxUint64/uint64(ex.D)
}

// Redeem verifies EVERY solution before atomically consuming a challenge nonce.
// Invalid submissions do not burn nonces. Store failures always fail closed.
func (e *Engine) Redeem(ctx context.Context, scope string, body json.RawMessage) (*ModernRedeem, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if !validModernScope(scope) {
		return nil, ErrInvalidScope
	}
	if len(body) == 0 || len(body) > maxModernBody {
		return modernFailure("invalid_body"), nil
	}
	var b modernSubmission
	if json.Unmarshal(body, &b) != nil {
		return modernFailure("invalid_body"), nil
	}
	if b.Token == "" {
		return modernFailure("missing_token"), nil
	}
	if b.Solutions == nil {
		return modernFailure("missing_solutions"), nil
	}
	var c modernClaims
	if len(b.Token) > maxModernBody/2 || !modernVerify(b.Token, e.secret, &c) {
		return modernFailure("invalid_token"), nil
	}
	if c.Scope != scope {
		return modernFailure("scope_mismatch"), nil
	}
	now := time.Now().UnixMilli()
	if c.Exp <= now {
		return modernFailure("expired"), nil
	}
	if c.Iat <= 0 || c.Iat > now || c.Exp-c.Iat > maxModernTTL.Milliseconds() || c.Exp <= c.Iat {
		return modernFailure("invalid_token"), nil
	}
	nbytes, err := hex.DecodeString(c.N)
	if err != nil || ((c.F == 0 || c.F == 1) && len(nbytes) != 25) || (c.F == 2 && len(nbytes) != 16) {
		return modernFailure("invalid_token"), nil
	}
	risks := []string{}
	if c.F == 0 || c.F == 1 {
		if c.C < 1 || c.C > 1000 || c.S < 1 || c.S > 256 || c.D < 1 || c.D > 16 {
			return modernFailure("invalid_token"), nil
		}
		if len(b.Solutions) != c.C {
			return modernFailure("invalid_solutions"), nil
		}
		fnv := modernFNV(2166136261, b.Token)
		for i, raw := range b.Solutions {
			if err = ctx.Err(); err != nil {
				return nil, err
			}
			nonce, _, ok := parseModernNonce(raw, false)
			if !ok {
				return modernFailure("invalid_solutions"), nil
			}
			saltSeed := modernFNV(fnv, fmt.Sprint(i+1))
			salt := modernPRNG(saltSeed, c.S)
			target := modernPRNG(modernFNV(saltSeed, "d"), c.D)
			if !modernSHAValid(salt, nonce, target) {
				return modernFailure("invalid_solution"), nil
			}
		}
		if c.EI != "" {
			var meta instrumentation.Metadata
			if !modernDecrypt(c.EI, e.secret, "cap:enc-v1", &meta) {
				return &ModernRedeem{Reason: "instr_corrupted", InstrError: true}, nil
			}
			f, r, xerr := modernInstr(&meta, b.Instr, b.Blocked, b.Timeout)
			if f != nil || xerr != nil {
				e.noteInstrFailure(ctx, &c, f)
				return f, xerr
			}
			risks = append(risks, r...)
		}
	} else if c.F == 2 {
		var env modernExpectedEnvelope
		if !modernDecrypt(c.EV, e.secret, "cap:fmt2-v1", &env) || len(env.Expected) < 1 || len(env.Expected) > 1100 {
			return modernFailure("invalid_token"), nil
		}
		if len(b.Solutions) != len(env.Expected) {
			return modernFailure("invalid_solutions"), nil
		}
		for i, ex := range env.Expected {
			if err = ctx.Err(); err != nil {
				return nil, err
			}
			var s modernSolution
			if len(b.Solutions[i]) == 0 || b.Solutions[i][0] != '{' || json.Unmarshal(b.Solutions[i], &s) != nil {
				return modernFailure("invalid_solution"), nil
			}
			switch ex.Protocol {
			case "sha256-pow":
				nonce, _, ok := parseModernNonce(s.Nonce, true)
				if !ok || len(ex.Salt) > 512 || !modernSHAValid(ex.Salt, nonce, ex.Target) {
					return modernFailure("invalid_solution"), nil
				}
			case "hashwx":
				if !verifyModernHashWX(ex, s.Nonce) {
					return modernFailure("invalid_solution"), nil
				}
			case "rsw":
				if !verifyRSW(ex.Y, s.Y) {
					return modernFailure("invalid_solution"), nil
				}
			case "instrumentation":
				f, r, xerr := modernInstr(ex.InstrMeta, s.Instr, s.Blocked, s.Timeout)
				if f != nil || xerr != nil {
					e.noteInstrFailure(ctx, &c, f)
					return f, xerr
				}
				risks = append(risks, r...)
			default:
				return modernFailure("invalid_solution"), nil
			}
		}
	} else {
		return modernFailure("invalid_token"), nil
	}
	if err = ctx.Err(); err != nil {
		return nil, err
	}
	now = time.Now().UnixMilli()
	if c.Exp <= now {
		return modernFailure("expired"), nil
	}
	// Generate randomness before committing a replay marker; entropy failure cannot burn a challenge.
	id, err := modernRandomHex(8)
	if err != nil {
		return nil, err
	}
	ver, err := modernRandomHex(15)
	if err != nil {
		return nil, err
	}
	token := id + ":" + ver
	sig := b.Token[strings.LastIndexByte(b.Token, '.')+1:]
	claimed, err := e.store.PutIfAbsent(ctx, e.storeKey("nonce", scope, sig), []byte{1}, time.UnixMilli(c.Exp))
	if err != nil {
		return modernFailure("nonce_store_error"), err
	}
	if !claimed {
		return modernFailure("already_redeemed"), nil
	}
	exp := time.Now().Add(e.tokenTTL).UnixMilli()
	record, _ := json.Marshal(struct {
		Scope   string `json:"scope"`
		Expires int64  `json:"expires"`
	}{scope, exp})
	// Never roll back a committed replay marker if token persistence fails.
	ok, err := e.store.PutIfAbsent(ctx, e.storeKey("token", scope, token), record, time.UnixMilli(exp))
	if err != nil {
		return modernFailure("token_store_error"), err
	}
	if !ok {
		return modernFailure("token_store_error"), errors.New("cap: token collision")
	}
	if c.DE && len(risks) > 0 {
		// Risk-driven escalation trigger: this redemption succeeded but the
		// instrumentation reported risk signals for the scope.
		e.bumpEscalation(ctx, c.Scope)
	}
	return &ModernRedeem{Success: true, Token: token, Expires: exp, Scope: scope, Iat: c.Iat, RiskFlags: risks}, nil
}
func (e *Engine) storeKey(kind, scope, value string) string {
	b, _ := json.Marshal([]string{kind, scope, value})
	return "cap:modern:" + kind + ":" + hex.EncodeToString(modernMAC(e.secret, string(b)))
}

// ValidateToken consumes a successful token exactly once. Scope is included in
// its lookup key so an incorrect scope cannot burn somebody else's token.
func (e *Engine) ValidateToken(ctx context.Context, scope, token string) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !validModernScope(scope) {
		return false, ErrInvalidScope
	}
	if len(token) != 47 || token[16] != ':' {
		return false, nil
	}
	if _, err := hex.DecodeString(token[:16]); err != nil {
		return false, nil
	}
	if _, err := hex.DecodeString(token[17:]); err != nil {
		return false, nil
	}
	value, ok, err := e.store.Take(ctx, e.storeKey("token", scope, token))
	if err != nil || !ok {
		return false, err
	}
	var r struct {
		Scope   string `json:"scope"`
		Expires int64  `json:"expires"`
	}
	if json.Unmarshal(value, &r) != nil {
		return false, errors.New("cap: corrupt token record")
	}
	return r.Scope == scope && time.Now().UnixMilli() < r.Expires, nil
}

package capserver

import (
	"bytes"
	"compress/flate"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// decodeModernInstr inflates a generated instrumentation blob.
func decodeModernInstr(t *testing.T, blob string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		t.Fatal(err)
	}
	r := flate.NewReader(bytes.NewReader(b))
	defer r.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}

// modernInstrCheckIDs returns, in script order, marker ids for the checks a
// blob injects, so two challenges can be compared by check selection. Markers
// are code-only substrings that survive every obfuscation level.
var modernCheckMarkers = []string{
	"MimeTypeArray.prototype", ".substr(i, sl)", "k.slice(0, pl)",
	"Function.prototype.toString.call(eval)", "window.external.toString",
	"navigator.appVersion", "navigator.productSub", "c.RENDERER)",
	"getOwnPropertyNames(document)", "window.process", "document.hasFocus()",
	"documentElement.getAttributeNames()", "window.exposedFn",
	"Function.prototype.bind", "getOwnPropertyDescriptors(navigator)",
	"getOwnPropertyNames(navigator)", "getOwnPropertyNames(window)) { if (",
	"lastIndexOf(",
}

func modernInstrCheckIDs(t *testing.T, blob string) []int {
	t.Helper()
	script := decodeModernInstr(t, blob)
	i := strings.Index(script, "false;try {")
	if i < 0 {
		t.Fatal("no injected check section")
	}
	rest := script[i:]
	m := regexp.MustCompile(`if \(!([a-z][a-z0-9]{11})`).FindStringSubmatch(rest)
	if m == nil {
		t.Fatal("no check opener")
	}
	end := strings.Index(rest, "if ("+m[1]+") {parent.postMessage")
	if end < 0 {
		t.Fatal("unterminated check section")
	}
	section := rest[:end]
	type hit struct {
		pos, id int
	}
	var hits []hit
	for id, marker := range modernCheckMarkers {
		if pos := strings.Index(section, marker); pos >= 0 {
			hits = append(hits, hit{pos, id})
		}
	}
	sort.Slice(hits, func(i, j int) bool { return hits[i].pos < hits[j].pos })
	ids := make([]int, len(hits))
	for i, h := range hits {
		ids[i] = h.id
	}
	return ids
}

func modernEscalationCounter(t *testing.T, e *Engine, scope string) (string, bool) {
	t.Helper()
	v, ok, err := e.store.Get(context.Background(), e.escalationStoreKey(scope))
	if err != nil {
		t.Fatal(err)
	}
	return string(v), ok
}

// blockedBody rewrites a solved submission so the client self-reports that the
// injected automated-browser checks fired (instr_blocked).
func blockedBody(t *testing.T, body json.RawMessage) json.RawMessage {
	t.Helper()
	var b modernSubmission
	if json.Unmarshal(body, &b) != nil {
		t.Fatal("body")
	}
	b.Blocked = true
	out, err := json.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Observation mode: the client self-reporting blocked still redeems, but with
// the instr_blocked_reported risk flag; blocking mode still fails.
func TestModernObservationBlockedReported(t *testing.T) {
	ctx := context.Background()
	e := testEngine(t, NewMemoryStore(200))
	opts := Options{ChallengeCount: 1, ChallengeDifficulty: 1, Instrumentation: true, InstrumentationOptions: InstrumentationOptions{BlockAutomatedBrowsers: false}}
	c, err := e.GenerateChallenge(ctx, "scope", opts)
	if err != nil {
		t.Fatal(err)
	}
	r, err := e.Redeem(ctx, "scope", blockedBody(t, solveModernV1(t, c)))
	if err != nil || !r.Success {
		t.Fatalf("observation redeem should succeed: %+v %v", r, err)
	}
	if !reflect.DeepEqual(r.RiskFlags, []string{"instr_blocked_reported"}) {
		t.Fatalf("risk flags %+v", r.RiskFlags)
	}
	if r.InstrError {
		t.Fatal("observation blocked report is not an instr error")
	}
	opts.InstrumentationOptions.BlockAutomatedBrowsers = true
	c, err = e.GenerateChallenge(ctx, "scope", opts)
	if err != nil {
		t.Fatal(err)
	}
	r, err = e.Redeem(ctx, "scope", blockedBody(t, solveModernV1(t, c)))
	if err != nil || r.Success || r.Reason != "instr_automated_browser" || !r.InstrError {
		t.Fatalf("blocking redeem should fail: %+v %v", r, err)
	}
	// Same semantics through the format 2 instrumentation protocol.
	c2, err := e.GenerateChallenge(ctx, "scope", Options{Format: 2, Protocols: []string{"instrumentation"}})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]any{"token": c2.Token, "solutions": []any{map[string]any{"blocked": true}}})
	r, err = e.Redeem(ctx, "scope", body)
	if err != nil || !r.Success || !reflect.DeepEqual(r.RiskFlags, []string{"instr_blocked_reported"}) {
		t.Fatalf("format 2 observation: %+v %v", r, err)
	}
}

// The engine derives the instrumentation selection seed from its secret and
// scope: one client always faces the same checks, across challenges; different
// scopes (or secrets) face different selections.
func TestModernInstrScopeSeedEngineDeterminism(t *testing.T) {
	ctx := context.Background()
	e := testEngine(t, nil)
	if e.instrScopeSeed("host/policy/ip") != e.instrScopeSeed("host/policy/ip") {
		t.Fatal("scope seed not deterministic")
	}
	if e.instrScopeSeed("host/policy/ip") == e.instrScopeSeed("host/policy/other") {
		t.Fatal("different scopes share a seed")
	}
	e2, err := NewEngine(EngineConfig{Secret: []byte("fedcba9876543210fedcba9876543210")})
	if err != nil {
		t.Fatal(err)
	}
	if e.instrScopeSeed("host/policy/ip") == e2.instrScopeSeed("host/policy/ip") {
		t.Fatal("different secrets share a seed")
	}
	opts := Options{Instrumentation: true, InstrumentationOptions: InstrumentationOptions{CheckCount: 18}}
	c1, err := e.GenerateChallenge(ctx, "host/policy/ip", opts)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := e.GenerateChallenge(ctx, "host/policy/ip", opts)
	if err != nil {
		t.Fatal(err)
	}
	if s1, s2 := modernInstrCheckIDs(t, c1.Instrumentation), modernInstrCheckIDs(t, c2.Instrumentation); !reflect.DeepEqual(s1, s2) {
		t.Fatal("same scope selected different checks across challenges")
	}
	c3, err := e.GenerateChallenge(ctx, "host/policy/other", opts)
	if err != nil {
		t.Fatal(err)
	}
	if reflect.DeepEqual(modernInstrCheckIDs(t, c1.Instrumentation), modernInstrCheckIDs(t, c3.Instrumentation)) {
		t.Fatal("different scopes selected the same checks")
	}
	// A host-supplied seed wins over the engine derivation.
	host := Options{Instrumentation: true, InstrumentationOptions: InstrumentationOptions{CheckCount: 18, ScopeSeed: "host-seed"}}
	c4, err := e.GenerateChallenge(ctx, "host/policy/ip", host)
	if err != nil {
		t.Fatal(err)
	}
	c5, err := e2.GenerateChallenge(ctx, "completely/other/scope", host)
	if err != nil {
		t.Fatal(err)
	}
	if s4, s5 := modernInstrCheckIDs(t, c4.Instrumentation), modernInstrCheckIDs(t, c5.Instrumentation); !reflect.DeepEqual(s4, s5) {
		t.Fatal("host-supplied scope seed should select the same checks everywhere")
	}
}

func TestEscalateOptionsBoundaries(t *testing.T) {
	inUse := Options{Format: 1, ChallengeCount: 1000, ChallengeDifficulty: 16, Instrumentation: true, InstrumentationOptions: InstrumentationOptions{ObfuscationLevel: 10}}
	escalateOptions(&inUse, 4)
	if inUse.ChallengeCount != 1000 || inUse.ChallengeDifficulty != 16 || inUse.InstrumentationOptions.ObfuscationLevel != 10 {
		t.Fatalf("hard caps: %+v", inUse)
	}
	f2 := Options{Format: 2, Protocols: []string{"sha256-pow", "hashwx", "rsw", "instrumentation"}, ChallengeCount: 1000, ChallengeDifficulty: 16, HashWXDifficulty: 1000000000, RSWT: 10000000, InstrumentationOptions: InstrumentationOptions{ObfuscationLevel: 10}}
	escalateOptions(&f2, 4)
	if f2.HashWXDifficulty != 1000000000 || f2.RSWT != 10000000 || f2.ChallengeDifficulty != 16 {
		t.Fatalf("format 2 hard caps: %+v", f2)
	}
	step := Options{Format: 2, Protocols: []string{"sha256-pow", "hashwx", "rsw"}, ChallengeCount: 50, ChallengeDifficulty: 4, HashWXDifficulty: 1000, RSWT: 75000}
	escalateOptions(&step, 1)
	if step.ChallengeDifficulty != 5 || step.ChallengeCount != 52 || step.HashWXDifficulty != 2000 || step.RSWT != 150000 {
		t.Fatalf("level 1 step: %+v", step)
	}
	escalateOptions(&step, 4)
	if step.ChallengeDifficulty != 9 || step.ChallengeCount != 60 || step.HashWXDifficulty != 32000 || step.RSWT != 2400000 {
		t.Fatalf("level 4 step: %+v", step)
	}
	// Zero ("use the default") and unused components are never touched.
	zero := Options{Format: 1, ChallengeCount: 0, ChallengeDifficulty: 0, HashWXDifficulty: 8, RSWT: 32, Instrumentation: true, InstrumentationOptions: InstrumentationOptions{}}
	escalateOptions(&zero, 4)
	if zero.ChallengeCount != 0 || zero.ChallengeDifficulty != 0 || zero.HashWXDifficulty != 8 || zero.RSWT != 32 || zero.InstrumentationOptions.ObfuscationLevel != 0 {
		t.Fatalf("zero/unused components moved: %+v", zero)
	}
	// Only the protocols the challenge actually uses escalate.
	partial := Options{Format: 2, Protocols: []string{"rsw"}, ChallengeCount: 4, ChallengeDifficulty: 4, HashWXDifficulty: 8, RSWT: 8}
	escalateOptions(&partial, 1)
	if partial.RSWT != 16 || partial.HashWXDifficulty != 8 || partial.ChallengeDifficulty != 4 || partial.ChallengeCount != 4 {
		t.Fatalf("unused protocols escalated: %+v", partial)
	}
	emptyProtocols := Options{Format: 2, RSWT: 8}
	escalateOptions(&emptyProtocols, 1)
	if emptyProtocols.RSWT != 16 {
		t.Fatalf("default rsw protocol not escalated: %+v", emptyProtocols)
	}
	noInstr := Options{Format: 1, Instrumentation: false, InstrumentationOptions: InstrumentationOptions{ObfuscationLevel: 5}}
	escalateOptions(&noInstr, 1)
	if noInstr.InstrumentationOptions.ObfuscationLevel != 5 {
		t.Fatalf("unused instrumentation escalated: %+v", noInstr)
	}
	// Invalid values are never rescued into validity.
	invalid := Options{Format: 1, ChallengeDifficulty: -3, ChallengeCount: -1, InstrumentationOptions: InstrumentationOptions{ObfuscationLevel: 99}}
	escalateOptions(&invalid, 4)
	if invalid.ChallengeDifficulty != -3 || invalid.ChallengeCount != -1 || invalid.InstrumentationOptions.ObfuscationLevel != 99 {
		t.Fatalf("invalid values rescued: %+v", invalid)
	}
	if _, err := testEngine(t, nil).GenerateChallenge(context.Background(), "scope", invalid); err == nil {
		t.Fatal("invalid options must still be rejected")
	}
}

// A risk counter in the Store drives difficulty escalation for challenges
// generated with DynamicEscalation; without the flag, neither reads nor
// writes happen. A blocked redemption does not consume its challenge, so one
// solved body can trigger repeatedly; escalated challenge values are then
// verified without redemption (solving an escalated challenge is what a real
// client pays for, not this test).
func TestModernEscalationTriggersAndLevels(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(500)
	e := testEngine(t, store)
	scope := "host/policy/ip"
	blockOpts := func(escalate bool) Options {
		return Options{ChallengeCount: 1, ChallengeDifficulty: 1, Instrumentation: true, DynamicEscalation: escalate, InstrumentationOptions: InstrumentationOptions{BlockAutomatedBrowsers: true, ObfuscationLevel: 3}}
	}
	// Without DynamicEscalation: a blocked redemption fails and records nothing.
	c, err := e.GenerateChallenge(ctx, scope, blockOpts(false))
	if err != nil {
		t.Fatal(err)
	}
	body := blockedBody(t, solveModernV1(t, c))
	r, err := e.Redeem(ctx, scope, body)
	if err != nil || r.Success || r.Reason != "instr_automated_browser" {
		t.Fatalf("%+v %v", r, err)
	}
	if _, ok := modernEscalationCounter(t, e, scope); ok {
		t.Fatal("counter written without DynamicEscalation")
	}
	// With DynamicEscalation: the same failure records one trigger.
	c, err = e.GenerateChallenge(ctx, scope, blockOpts(true))
	if err != nil {
		t.Fatal(err)
	}
	body = blockedBody(t, solveModernV1(t, c))
	if _, err = e.Redeem(ctx, scope, body); err != nil {
		t.Fatal(err)
	}
	if v, ok := modernEscalationCounter(t, e, scope); !ok || v != "1" {
		t.Fatalf("counter %q %v", v, ok)
	}
	// The next challenge for the scope is escalated by one level.
	c, err = e.GenerateChallenge(ctx, scope, blockOpts(true))
	if err != nil {
		t.Fatal(err)
	}
	var claims modernClaims
	if !modernVerify(c.Token, e.secret, &claims) {
		t.Fatal("JWT")
	}
	if claims.C != 3 || claims.D != 2 {
		t.Fatalf("escalated sha256 knobs: c=%d d=%d", claims.C, claims.D)
	}
	if !claims.DE {
		t.Fatal("escalation flag missing from claims")
	}
	if s := decodeModernInstr(t, c.Instrumentation); !strings.HasPrefix(s, "var ") {
		t.Fatalf("obfuscation not escalated past level 3: %.40s", s)
	}
	// Escalation applies only when the challenge opts enable it.
	plain, err := e.GenerateChallenge(ctx, scope, blockOpts(false))
	if err != nil {
		t.Fatal(err)
	}
	var plainClaims modernClaims
	if !modernVerify(plain.Token, e.secret, &plainClaims) || plainClaims.C != 1 || plainClaims.D != 1 || plainClaims.DE {
		t.Fatalf("un-escalated challenge: %+v", plainClaims)
	}
	// The blocked body was never consumed: repeating it still fails, records
	// another trigger each time, and the level caps at 4.
	for i := 2; i <= 5; i++ {
		if r, err = e.Redeem(ctx, scope, body); err != nil || r.Success || r.Reason != "instr_automated_browser" {
			t.Fatalf("repeat %d: %+v %v", i, r, err)
		}
		if v, _ := modernEscalationCounter(t, e, scope); v != fmt.Sprint(i) {
			t.Fatalf("counter after %d triggers: %q", i, v)
		}
	}
	c, err = e.GenerateChallenge(ctx, scope, blockOpts(true))
	if err != nil {
		t.Fatal(err)
	}
	modernVerify(c.Token, e.secret, &claims)
	if claims.D != 5 || claims.C != 9 {
		t.Fatalf("level cap 4: c=%d d=%d", claims.C, claims.D)
	}
	// Successful redemptions without risk flags never trigger.
	okOpts := Options{ChallengeCount: 1, ChallengeDifficulty: 1, DynamicEscalation: true}
	for i := 0; i < 2; i++ {
		c, err = e.GenerateChallenge(ctx, "clean/scope", okOpts)
		if err != nil {
			t.Fatal(err)
		}
		if r, err = e.Redeem(ctx, "clean/scope", solveModernV1(t, c)); err != nil || !r.Success || len(r.RiskFlags) != 0 {
			t.Fatalf("%+v %v", r, err)
		}
	}
	if _, presence := modernEscalationCounter(t, e, "clean/scope"); presence {
		t.Fatal("clean redemption triggered escalation")
	}
	// A successful redemption carrying risk flags triggers once.
	obsOpts := Options{ChallengeCount: 1, ChallengeDifficulty: 1, Instrumentation: true, DynamicEscalation: true, InstrumentationOptions: InstrumentationOptions{BlockAutomatedBrowsers: false}}
	c, err = e.GenerateChallenge(ctx, "obs/scope", obsOpts)
	if err != nil {
		t.Fatal(err)
	}
	if r, err = e.Redeem(ctx, "obs/scope", blockedBody(t, solveModernV1(t, c))); err != nil || !r.Success || len(r.RiskFlags) != 1 {
		t.Fatalf("%+v %v", r, err)
	}
	if v, ok := modernEscalationCounter(t, e, "obs/scope"); !ok || v != "1" {
		t.Fatalf("risk-flag redemption did not trigger: %q %v", v, ok)
	}
	// A Detect risk flag (native_tamper) triggers as well.
	c, err = e.GenerateChallenge(ctx, "tamper/scope", obsOpts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = e.Redeem(ctx, "tamper/scope", tamperProbeBody(t, e, c)); err != nil {
		t.Fatal(err)
	}
	if v, ok := modernEscalationCounter(t, e, "tamper/scope"); !ok || v != "1" {
		t.Fatalf("detect risk flag did not trigger: %q %v", v, ok)
	}
	// Format 2: a blocked instrumentation solution triggers, then hashwx and
	// rsw knobs escalate too (verified from the challenge, without solving).
	instrOnly := Options{Format: 2, Protocols: []string{"instrumentation"}, DynamicEscalation: true, InstrumentationOptions: InstrumentationOptions{BlockAutomatedBrowsers: true, ObfuscationLevel: 1}}
	c2, err := e.GenerateChallenge(ctx, "fmt2/scope", instrOnly)
	if err != nil {
		t.Fatal(err)
	}
	f2Body, _ := json.Marshal(map[string]any{"token": c2.Token, "solutions": []any{map[string]any{"blocked": true}}})
	if r, err = e.Redeem(ctx, "fmt2/scope", f2Body); err != nil || r.Success || r.Reason != "instr_automated_browser" {
		t.Fatalf("format 2 blocked: %+v %v", r, err)
	}
	if v, ok := modernEscalationCounter(t, e, "fmt2/scope"); !ok || v != "1" {
		t.Fatalf("format 2 trigger: %q %v", v, ok)
	}
	f2Opts := Options{Format: 2, Protocols: []string{"sha256-pow", "hashwx", "rsw"}, ChallengeCount: 2, ChallengeDifficulty: 1, HashWXDifficulty: 8, HashWXChallengeCount: 2, RSWT: 32, DynamicEscalation: true}
	c2, err = e.GenerateChallenge(ctx, "fmt2/scope", f2Opts)
	if err != nil {
		t.Fatal(err)
	}
	shaCount, hashwxD, rswT, targetLen := 0, 0, 0, 0
	for _, ch := range c2.Challenges {
		switch ch.Protocol {
		case "sha256-pow":
			shaCount++
			targetLen = len(ch.Payload.(map[string]any)["target"].(string))
		case "hashwx":
			hashwxD = ch.Payload.(map[string]any)["d"].(int)
		case "rsw":
			rswT = ch.Payload.(map[string]any)["t"].(int)
		}
	}
	if shaCount != 4 || targetLen != 2 || hashwxD != 8 || rswT != 64 {
		t.Fatalf("format 2 escalation: sha=%d targetLen=%d hashwx=%d rswT=%d", shaCount, targetLen, hashwxD, rswT)
	}
}

// tamperProbeBody solves a format 1 challenge and answers the instrumentation
// with a passing probe whose tamper map reports an overridden native function
// (the non-gating native_tamper risk flag).
func tamperProbeBody(t *testing.T, e *Engine, c *ModernChallenge) json.RawMessage {
	t.Helper()
	var claims modernClaims
	if !modernVerify(c.Token, e.secret, &claims) {
		t.Fatal("JWT")
	}
	var meta struct {
		ID           string   `json:"id"`
		ExpectedVals []int32  `json:"expectedVals"`
		Vars         []string `json:"vars"`
	}
	if !modernDecrypt(claims.EI, e.secret, "cap:enc-v1", &meta) {
		t.Fatal("GCM")
	}
	state := map[string]int32{}
	for i, v := range meta.Vars {
		state[v] = meta.ExpectedVals[i]
	}
	fontWidths := make([]any, 17)
	for i := range fontWidths {
		fontWidths[i] = 72.5 + float64(i)*1.25
	}
	probe := map[string]any{
		"ua":            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/154.0.0.0 Safari/537.36",
		"productSub":    "20030107",
		"oscpu":         "__undefined",
		"uaDataPresent": true,
		"uaData":        map[string]any{"mobile": false, "brands": []any{"Google Chrome/154"}},
		"plugins":       map[string]any{"length": 5},
		"engine":        map[string]any{"hasMozInnerScreenX": false, "hasChrome": true},
		"screen":        map[string]any{"width": 1920, "height": 1080},
		"outerWH":       []any{1920.0, 1040.0},
		"isExtended":    nil,
		"fontWidths":    fontWidths,
		"webdriver":     false,
		"tamper": map[string]any{
			"getParameterWebGL": false, "toDataURL": true, "getImageData": true, "permissionsQuery": true, "fnToString": true,
		},
	}
	solutions := make([]uint64, claims.C)
	fnv := modernFNV(2166136261, c.Token)
	for i := range solutions {
		seed := modernFNV(fnv, fmt.Sprint(i+1))
		salt := modernPRNG(seed, claims.S)
		target := modernPRNG(modernFNV(seed, "d"), claims.D)
		for n := uint64(0); ; n++ {
			if modernSHAValid(salt, fmt.Sprint(n), target) {
				solutions[i] = n
				break
			}
		}
	}
	body, err := json.Marshal(map[string]any{
		"token":     c.Token,
		"solutions": solutions,
		"instr":     map[string]any{"i": meta.ID, "state": state, "p": probe},
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

type recordingStore struct {
	Store
	mu   sync.Mutex
	puts []struct {
		key string
		exp time.Time
	}
}

func (s *recordingStore) Put(ctx context.Context, key string, value []byte, exp time.Time) error {
	if err := s.Store.Put(ctx, key, value, exp); err != nil {
		return err
	}
	s.mu.Lock()
	s.puts = append(s.puts, struct {
		key string
		exp time.Time
	}{key, exp})
	s.mu.Unlock()
	return nil
}

// The counter lives under a 24h sliding TTL refreshed by every trigger, and an
// expired counter stops escalating without any error.
func TestModernEscalationTTL(t *testing.T) {
	ctx := context.Background()
	inner := NewMemoryStore(200)
	rec := &recordingStore{Store: inner}
	e := testEngine(t, rec)
	scope := "ttl/scope"
	opts := Options{ChallengeCount: 1, ChallengeDifficulty: 2, Instrumentation: true, DynamicEscalation: true, InstrumentationOptions: InstrumentationOptions{BlockAutomatedBrowsers: true, ObfuscationLevel: 1}}
	key := e.escalationStoreKey(scope)
	escalatePuts := func() []time.Time {
		rec.mu.Lock()
		defer rec.mu.Unlock()
		var out []time.Time
		for _, p := range rec.puts {
			if p.key == key {
				out = append(out, p.exp)
			}
		}
		return out
	}
	trigger := func() {
		c, err := e.GenerateChallenge(ctx, scope, opts)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = e.Redeem(ctx, scope, blockedBody(t, solveModernV1(t, c))); err != nil {
			t.Fatal(err)
		}
	}
	trigger()
	puts := escalatePuts()
	if len(puts) != 1 {
		t.Fatalf("escalation puts: %d", len(puts))
	}
	if d := time.Until(puts[0]); d <= 0 || d > 24*time.Hour {
		t.Fatalf("TTL not ~24h: %v", d)
	}
	trigger()
	puts = escalatePuts()
	if len(puts) != 2 || !puts[1].After(puts[0]) {
		t.Fatalf("TTL not sliding: %v", puts)
	}
	// An expired counter reads as zero and escalates nothing.
	if err := inner.Put(ctx, key, []byte("3"), time.Now().Add(150*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if lvl := e.escalationLevel(ctx, scope); lvl != 3 {
		t.Fatalf("level before expiry: %d", lvl)
	}
	time.Sleep(200 * time.Millisecond)
	if lvl := e.escalationLevel(ctx, scope); lvl != 0 {
		t.Fatalf("level after expiry: %d", lvl)
	}
	c, err := e.GenerateChallenge(ctx, scope, opts)
	if err != nil {
		t.Fatal(err)
	}
	var claims modernClaims
	if !modernVerify(c.Token, e.secret, &claims) || claims.D != 2 {
		t.Fatalf("expired counter still escalated: %+v", claims)
	}
	// A corrupt counter is advisory: treated as absent, never an error.
	if err := inner.Put(ctx, key, []byte("not-a-number"), time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if lvl := e.escalationLevel(ctx, scope); lvl != 0 {
		t.Fatalf("corrupt counter escalated: %d", lvl)
	}
}

// Concurrent triggers for one scope tolerate the non-atomic read-modify-write
// (worst case an undercount); they never lose the counter or panic. The
// format 2 instrumentation-only protocol triggers the same counter race as a
// blocked format 1 redemption, without paying for solving (possibly
// escalated) proof-of-work.
func TestModernEscalationRaceTolerance(t *testing.T) {
	ctx := context.Background()
	e := testEngine(t, NewMemoryStore(5000))
	scope := "race/scope"
	opts := Options{Format: 2, Protocols: []string{"instrumentation"}, DynamicEscalation: true, InstrumentationOptions: InstrumentationOptions{BlockAutomatedBrowsers: true, ObfuscationLevel: 1}}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c, err := e.GenerateChallenge(ctx, scope, opts)
			if err != nil {
				t.Error(err)
				return
			}
			body, err := json.Marshal(map[string]any{"token": c.Token, "solutions": []any{map[string]any{"blocked": true}}})
			if err != nil {
				t.Error(err)
				return
			}
			r, err := e.Redeem(ctx, scope, body)
			if err != nil || r.Success || r.Reason != "instr_automated_browser" {
				t.Errorf("%+v %v", r, err)
			}
		}()
	}
	wg.Wait()
	v, ok := modernEscalationCounter(t, e, scope)
	if !ok {
		t.Fatal("concurrent triggers lost the counter entirely")
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil || n < 1 || n > 32 {
		t.Fatalf("counter %q outside tolerated range 1..32 (err %v)", v, err)
	}
	if lvl := e.escalationLevel(ctx, scope); lvl < 1 {
		t.Fatalf("level after concurrent triggers: %d", lvl)
	}
}

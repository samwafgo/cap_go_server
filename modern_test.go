package capserver

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var modernTestSecret = []byte("0123456789abcdef0123456789abcdef")

func testEngine(t *testing.T, s Store) *Engine {
	t.Helper()
	e, err := NewEngine(EngineConfig{Secret: modernTestSecret, Store: s})
	if err != nil {
		t.Fatal(err)
	}
	return e
}
func solveModernV1(t *testing.T, c *ModernChallenge) json.RawMessage {
	t.Helper()
	solutions := make([]uint64, c.Challenge.C)
	fnv := modernFNV(2166136261, c.Token)
	for i := range solutions {
		seed := modernFNV(fnv, fmt.Sprint(i+1))
		salt := modernPRNG(seed, c.Challenge.S)
		target := modernPRNG(modernFNV(seed, "d"), c.Challenge.D)
		for n := uint64(0); ; n++ {
			if modernSHAValid(salt, fmt.Sprint(n), target) {
				solutions[i] = n
				break
			}
		}
	}
	b, _ := json.Marshal(map[string]any{"token": c.Token, "solutions": solutions})
	return b
}
func TestModernAtomicReplayAndScope(t *testing.T) {
	ctx := context.Background()
	e := testEngine(t, nil)
	c, err := e.GenerateChallenge(ctx, "host/policy/ip", Options{ChallengeCount: 2, ChallengeDifficulty: 1})
	if err != nil {
		t.Fatal(err)
	}
	body := solveModernV1(t, c)
	bad, err := e.Redeem(ctx, "other", body)
	if err != nil || bad.Reason != "scope_mismatch" {
		t.Fatalf("scope: %+v %v", bad, err)
	}
	var success atomic.Int32
	var token string
	var mu sync.Mutex
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := e.Redeem(ctx, "host/policy/ip", body)
			if err != nil {
				t.Error(err)
				return
			}
			if r.Success {
				success.Add(1)
				mu.Lock()
				token = r.Token
				mu.Unlock()
			} else if r.Reason != "already_redeemed" {
				t.Errorf("unexpected %+v", r)
			}
		}()
	}
	wg.Wait()
	if success.Load() != 1 {
		t.Fatalf("redemption winners %d", success.Load())
	}
	if ok, err := e.ValidateToken(ctx, "other", token); ok || err != nil {
		t.Fatalf("wrong scope token: %v %v", ok, err)
	}
	success.Store(0)
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := e.ValidateToken(ctx, "host/policy/ip", token)
			if err != nil {
				t.Error(err)
			}
			if ok {
				success.Add(1)
			}
		}()
	}
	wg.Wait()
	if success.Load() != 1 {
		t.Fatalf("token winners %d", success.Load())
	}
}
func TestModernInvalidDoesNotConsume(t *testing.T) {
	ctx := context.Background()
	e := testEngine(t, nil)
	c, _ := e.GenerateChallenge(ctx, "scope", Options{ChallengeCount: 1, ChallengeDifficulty: 1})
	body := solveModernV1(t, c)
	var bad map[string]any
	json.Unmarshal(body, &bad)
	bad["solutions"] = []any{-1}
	b, _ := json.Marshal(bad)
	r, err := e.Redeem(ctx, "scope", b)
	if err != nil || r.Success {
		t.Fatal(r, err)
	}
	r, err = e.Redeem(ctx, "scope", body)
	if err != nil || !r.Success {
		t.Fatal(r, err)
	}
}
func TestModernNonceBounds(t *testing.T) {
	for _, v := range []string{`-1`, `1.5`, `1e2`, `9007199254740992`, `"18446744073709551616"`, `"000000000000000000000"`, `"+1"`, `null`, `true`} {
		if _, _, ok := parseModernNonce(json.RawMessage(v), true); ok {
			t.Errorf("accepted %s", v)
		}
	}
	for _, v := range []string{`0`, `9007199254740991`, `"18446744073709551615"`, `"00001"`} {
		if _, _, ok := parseModernNonce(json.RawMessage(v), true); !ok {
			t.Errorf("rejected %s", v)
		}
	}
	if _, _, ok := parseModernNonce(json.RawMessage(`"1"`), false); ok {
		t.Fatal("format 1 string")
	}
}
func TestModernExpiryAndTampering(t *testing.T) {
	ctx := context.Background()
	e := testEngine(t, nil)
	c, _ := e.GenerateChallenge(ctx, "scope", Options{ChallengeCount: 1, ChallengeDifficulty: 1})
	body := solveModernV1(t, c)
	var b modernSubmission
	json.Unmarshal(body, &b)
	var claims modernClaims
	modernVerify(c.Token, e.secret, &claims)
	claims.Exp = time.Now().Add(-time.Second).UnixMilli()
	b.Token, _ = modernSign(claims, e.secret)
	raw, _ := json.Marshal(b)
	r, err := e.Redeem(ctx, "scope", raw)
	if err != nil || r.Reason != "expired" {
		t.Fatal(r, err)
	}
	b.Token = c.Token + "!"
	raw, _ = json.Marshal(b)
	r, err = e.Redeem(ctx, "scope", raw)
	if err != nil || r.Reason != "invalid_token" {
		t.Fatal(r, err)
	}
	claims.Exp = time.Now().Add(time.Minute).UnixMilli()
	claims.F = 99
	b.Token, _ = modernSign(claims, e.secret)
	raw, _ = json.Marshal(b)
	r, err = e.Redeem(ctx, "scope", raw)
	if err != nil || r.Reason != "invalid_token" {
		t.Fatal(r, err)
	}
}

type brokenModernStore struct {
	Store
	failTake bool
}

func (s brokenModernStore) PutIfAbsent(context.Context, string, []byte, time.Time) (bool, error) {
	return false, errors.New("offline")
}
func (s brokenModernStore) Take(context.Context, string) ([]byte, bool, error) {
	return nil, false, errors.New("offline")
}
func TestModernStoreFailClosed(t *testing.T) {
	ctx := context.Background()
	e := testEngine(t, brokenModernStore{})
	c, _ := e.GenerateChallenge(ctx, "scope", Options{ChallengeCount: 1, ChallengeDifficulty: 1})
	r, err := e.Redeem(ctx, "scope", solveModernV1(t, c))
	if err == nil || r.Success || r.Reason != "nonce_store_error" {
		t.Fatal(r, err)
	}
	ok, err := e.ValidateToken(ctx, "scope", strings.Repeat("0", 16)+":"+strings.Repeat("0", 30))
	if ok || err == nil {
		t.Fatal(ok, err)
	}
}
func TestModernConfigBoundaries(t *testing.T) {
	if _, err := NewEngine(EngineConfig{Secret: []byte("short")}); err == nil {
		t.Fatal("short secret")
	}
	e := testEngine(t, nil)
	for _, o := range []Options{{Format: 3}, {ChallengeCount: 1001}, {ChallengeSize: 257}, {ChallengeDifficulty: 17}, {HashWXChallengeCount: 65}, {RSWT: 10000001}, {ExpiresMs: -1}, {Format: 2, Protocols: []string{"unknown"}}} {
		if _, err := e.GenerateChallenge(context.Background(), "scope", o); err == nil {
			t.Fatalf("accepted %+v", o)
		}
	}
	if _, err := e.GenerateChallenge(context.Background(), "", Options{}); err == nil {
		t.Fatal("empty scope")
	}
}

// Node is a development oracle ONLY; production uses no external runtime.
// Set CAP_UPSTREAM_SRC to the pinned core/src directory to run elsewhere.
func nodeOracle(t *testing.T, input any) json.RawMessage {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node25 oracle unavailable")
	}
	src := os.Getenv("CAP_UPSTREAM_SRC")
	if src == "" {
		src = "/tmp/cap-research-tuPdoDsS/cap-af624b9f15cb03f1f8194fb4c9f262ac34984923/core/src"
	}
	if _, err = os.Stat(filepath.Join(src, "index.js")); err != nil {
		t.Skip("pinned upstream source unavailable; set CAP_UPSTREAM_SRC")
	}
	script := `
import fs from 'node:fs'; import {pathToFileURL} from 'node:url';
const q=JSON.parse(fs.readFileSync(0,'utf8')); const root=process.env.CAP_UPSTREAM_SRC;
const core=await import(pathToFileURL(root+'/index.js'));const crypto=await import(pathToFileURL(root+'/crypto.js'));const prng=await import(pathToFileURL(root+'/prng.js'));const hw=await import(pathToFileURL(root+'/hashwx.js'));
const secret=q.secret;let c=q.challenge;
if(q.generate)c=await core.generateChallenge(secret,{...q.options,keypair:q.key,scope:q.scope});
const p=crypto.jwtVerify(c.token,secret);if(!p)throw Error('Go JWT rejected');let solutions=[];let extra={};
const instr=(m)=>({i:m.id,state:Object.fromEntries(m.vars.map((v,i)=>[v,m.expectedVals[i]]))});
if(c.format===2){const expected=crypto.decryptGcm(p.ev,secret,'cap:fmt2-v1').expected;
for(let i=0;i<c.challenges.length;i++){let {protocol,payload:v}=c.challenges[i];if(protocol==='sha256-pow'){let n=0;while(!crypto.sha256Hex(v.salt+n).startsWith(v.target))n++;solutions.push({nonce:n});}
else if(protocol==='rsw'){const N=BigInt('0x'+v.N);let y=BigInt('0x'+v.x);for(let j=0;j<v.t;j++)y=y*y%N;solutions.push({y:y.toString(16)});}
else if(protocol==='hashwx'){const state=await hw.hashwxReady();let n=0n;while(hw.hashwxHash(state,hw.hashwxSeed(Buffer.from(v.c,'hex'),n/BigInt(v.n)),n)>hw.hashwxTarget(v.d))n++;solutions.push({nonce:n.toString()});}
else if(protocol==='instrumentation')solutions.push({instr:instr(expected[i].instrMeta)});
}}
else{for(let i=0;i<c.challenge.c;i++){const salt=prng.prng(c.token+(i+1),c.challenge.s),target=prng.prng(c.token+(i+1)+'d',c.challenge.d);let n=0;while(!crypto.sha256Hex(salt+n).startsWith(target))n++;solutions.push(n);}if(p.ei)extra.instr=instr(crypto.decryptGcm(p.ei,secret));}
const body={token:c.token,solutions,...extra};const result=await core.validateChallenge(secret,body,{scope:q.scope});if(!result.success)throw Error(JSON.stringify(result));console.log(JSON.stringify({challenge:c,body,result}));`
	cmd := exec.Command(node, "--input-type=module", "-e", script)
	cmd.Env = append(os.Environ(), "CAP_UPSTREAM_SRC="+src)
	raw, _ := json.Marshal(input)
	cmd.Stdin = strings.NewReader(string(raw))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Node oracle: %v\n%s", err, out)
	}
	return out
}
func TestModernNodeOracleBidirectional(t *testing.T) {
	ctx := context.Background()
	key, err := GenerateRSWKeypair()
	if err != nil {
		t.Fatal(err)
	}
	e, err := NewEngine(EngineConfig{Secret: modernTestSecret, RSWKey: key})
	if err != nil {
		t.Fatal(err)
	}
	for _, format := range []int{1, 2} {
		for _, direction := range []string{"go-to-node", "node-to-go"} {
			t.Run(fmt.Sprintf("format%d/%s", format, direction), func(t *testing.T) {
				opts := Options{Format: format, ChallengeCount: 2, ChallengeSize: 9, ChallengeDifficulty: 1, HashWXDifficulty: 8, HashWXChallengeCount: 2, HashWXNoncesPerHash: 4, RSWT: 32, Instrumentation: true, InstrumentationOptions: InstrumentationOptions{ObfuscationLevel: 1}}
				if format == 2 {
					opts.Protocols = []string{"sha256-pow", "rsw", "hashwx", "instrumentation"}
				}
				q := map[string]any{"secret": string(modernTestSecret), "scope": "oracle-scope", "key": key}
				if direction == "go-to-node" {
					c, err := e.GenerateChallenge(ctx, "oracle-scope", opts)
					if err != nil {
						t.Fatal(err)
					}
					q["challenge"] = c
				} else {
					q["generate"] = true
					q["options"] = map[string]any{"format": format, "protocols": opts.Protocols, "challengeCount": 2, "challengeSize": 9, "challengeDifficulty": 1, "hashwxDifficulty": 8, "hashwxChallengeCount": 2, "hashwxNoncesPerHash": 4, "t": 32, "instrumentation": map[string]any{"obfuscationLevel": 1}}
				}
				var oracle struct {
					Body json.RawMessage `json:"body"`
				}
				if err = json.Unmarshal(nodeOracle(t, q), &oracle); err != nil {
					t.Fatal(err)
				}
				r, err := e.Redeem(ctx, "oracle-scope", oracle.Body)
				if err != nil || !r.Success {
					t.Fatalf("Go rejects Node-compatible challenge: %+v %v", r, err)
				}
				ok, err := e.ValidateToken(ctx, "oracle-scope", r.Token)
				if err != nil || !ok {
					t.Fatal(ok, err)
				}
			})
		}
		// A risk-escalated challenge (raised difficulty/count/T/obfuscation and
		// the signed escalation claim) stays fully upstream-solvable.
		t.Run(fmt.Sprintf("format%d/escalated", format), func(t *testing.T) {
			if err := e.store.Put(ctx, e.escalationStoreKey("oracle-scope"), []byte("3"), time.Now().Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			opts := Options{Format: format, ChallengeCount: 2, ChallengeSize: 9, ChallengeDifficulty: 1, HashWXDifficulty: 8, HashWXChallengeCount: 2, HashWXNoncesPerHash: 4, RSWT: 32, Instrumentation: true, InstrumentationOptions: InstrumentationOptions{ObfuscationLevel: 1}, DynamicEscalation: true}
			if format == 2 {
				opts.Protocols = []string{"sha256-pow", "rsw", "hashwx", "instrumentation"}
			}
			c, err := e.GenerateChallenge(ctx, "oracle-scope", opts)
			if err != nil {
				t.Fatal(err)
			}
			var claims modernClaims
			if !modernVerify(c.Token, e.secret, &claims) {
				t.Fatal("escalated challenge JWT")
			}
			if !claims.DE {
				t.Fatal("escalation claim missing")
			}
			q := map[string]any{"secret": string(modernTestSecret), "scope": "oracle-scope", "key": key, "challenge": c}
			var oracle struct {
				Body json.RawMessage `json:"body"`
			}
			if err = json.Unmarshal(nodeOracle(t, q), &oracle); err != nil {
				t.Fatal(err)
			}
			r, err := e.Redeem(ctx, "oracle-scope", oracle.Body)
			if err != nil || !r.Success {
				t.Fatalf("Go rejects escalated challenge: %+v %v", r, err)
			}
		})
	}
}

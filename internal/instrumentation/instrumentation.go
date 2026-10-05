// Package instrumentation implements Cap's browser instrumentation protocol in Go.
// Adapted from tiagozip/cap af624b9f15cb03f1f8194fb4c9f262ac34984923 (Apache-2.0).
package instrumentation

import (
	"bytes"
	"compress/flate"
	crand "crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"time"
)

//go:embed browser.js.tmpl
var browserTemplate string

//go:embed block_checks.json
var blockChecksJSON []byte

var ErrUnsupportedObfuscationLevel = errors.New("instrumentation: obfuscation level must be in 1-10 (0 selects the default: 6 when blocking automated browsers, otherwise 3)")
var ErrUnsupportedCheckCount = errors.New("instrumentation: check count must be in 1-18 (0 selects the default: 18 when blocking automated browsers, otherwise 8)")

type Options struct {
	BlockAutomatedBrowsers bool
	ObfuscationLevel       int
	// CheckCount selects how many of the available automated-browser checks
	// are injected into the generated script (1-18; the current check set is
	// 18). 0 selects the default: every available check (18) when
	// BlockAutomatedBrowsers is set, otherwise the upstream default sample of
	// 8. Out-of-range values are rejected, never silently clamped.
	CheckCount int
	// ScopeSeed switches check selection from per-challenge randomness to a
	// deterministic shuffle keyed by the seed: the same seed always injects
	// the same selection, so a client bound to one scope cannot re-roll a
	// challenge hoping for an easier check sample. Only the check selection
	// is deterministic; variable names, initial values, arithmetic and salts
	// stay per-challenge random. Empty keeps per-challenge random selection
	// (the upstream behavior). The engine derives this from its secret and
	// scope; direct callers must never fill it from untrusted input.
	ScopeSeed string
}
type Metadata struct {
	ID                     string   `json:"id"`
	ExpectedVals           []int32  `json:"expectedVals"`
	Vars                   []string `json:"vars"`
	BlockAutomatedBrowsers bool     `json:"blockAutomatedBrowsers"`
	Expires                int64    `json:"expires,omitempty"`
}
type Check struct {
	ID     string `json:"id"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail,omitempty"`
	Gating bool   `json:"gating"`
}
type Result struct {
	Success   bool     `json:"success"`
	Reason    string   `json:"reason,omitempty"`
	RiskFlags []string `json:"riskFlags"`
	BlockedBy []string `json:"blockedBy,omitempty"`
	Checks    []Check  `json:"checks,omitempty"`
}

type randomSource struct {
	r   io.Reader
	err error
}

func (r *randomSource) number(n int) int {
	if r.err != nil {
		return 0
	}
	v, e := crand.Int(r.r, big.NewInt(int64(n)))
	if e != nil {
		r.err = e
		return 0
	}
	return int(v.Int64())
}
func (r *randomSource) between(a, b int) int { return a + r.number(b-a+1) }
func (r *randomSource) identifier() string {
	const letters = "abcdefghijklmnopqrstuvwxyz"
	const chars = letters + "0123456789"
	out := make([]byte, 12)
	out[0] = letters[r.number(len(letters))]
	for i := 1; i < len(out); i++ {
		out[i] = chars[r.number(len(chars))]
	}
	return string(out)
}

// Generate returns raw-DEFLATE, standard-base64 encoded browser JavaScript and
// private expected metadata. The caller must authenticate/encrypt metadata and
// set Expires to the challenge's expiry in milliseconds. No JS engine is used.
//
// The automated-browser checks are injected whenever instrumentation is
// generated, including when BlockAutomatedBrowsers is false (observation
// mode): the client then still reports blocked on a hit, and the server side
// surfaces that as a risk flag instead of a failure. BlockAutomatedBrowsers
// only selects whether a client-reported or probe-detected hit fails the
// redemption (metadata) — it no longer controls injection.
func Generate(opts Options, reader io.Reader) (string, Metadata, error) {
	level := opts.ObfuscationLevel
	if level == 0 {
		if opts.BlockAutomatedBrowsers {
			level = 6
		} else {
			level = 3
		}
	}
	if level < 1 || level > 10 {
		return "", Metadata{}, ErrUnsupportedObfuscationLevel
	}
	if reader == nil {
		reader = crand.Reader
	}
	r := &randomSource{r: reader}
	id := make([]byte, 16)
	if _, err := io.ReadFull(reader, id); err != nil {
		return "", Metadata{}, err
	}
	meta := Metadata{ID: hex.EncodeToString(id), Vars: make([]string, 4), ExpectedVals: make([]int32, 4), BlockAutomatedBrowsers: opts.BlockAutomatedBrowsers}
	initial := make([]int32, 4)
	seen := map[string]bool{}
	for i := range meta.Vars {
		for attempts := 0; ; attempts++ {
			if attempts >= 64 {
				return "", Metadata{}, errors.New("instrumentation: random source produced duplicate identifiers")
			}
			name := r.identifier()
			if r.err != nil {
				return "", Metadata{}, r.err
			}
			if !seen[name] {
				seen[name] = true
				meta.Vars[i] = name
				break
			}
		}
		initial[i] = int32(r.between(10, 250))
		meta.ExpectedVals[i] = initial[i]
	}
	correct := r.between(1000, 9000)
	bad := r.between(1000, 8999)
	if bad >= correct {
		bad++
	}
	meta.ExpectedVals[0] ^= int32(correct)
	// Helpers reproduce JavaScript prototype lookup and DOM ancestry semantics.
	const helpers = `function capFnHelper(a,b,c){function F(d){this.v=function(){return this.k^d;}};var p={k:c};var i=new F(a);i.k=b;F.prototype=p;return i.v()|(new F(b)).v();}function capDomHelper(x,y,z){var d=document.createElement('div');d.style.display='none';document.body.appendChild(d);function A(p,v){for(var i=0;i<8;i++){var c=document.createElement('div');p.appendChild(c);c.innerText=v;if((v&1)==0)p=c;v=v>>1;}return p;}function B(n,r,s){if(!n||n==r)return s%256;while(n.children.length>0)n.removeChild(n.lastElementChild);return B(n.parentNode,r,s+parseInt(n.innerText));}var s=B(A(A(A(d,x),y),z),d,0);d.parentNode.removeChild(d);return s;}`
	var equations strings.Builder
	equations.WriteString(helpers)
	fmt.Fprintf(&equations, "%s=%s^(navigator.userAgent?%d:%d);", meta.Vars[0], meta.Vars[0], correct, bad)
	for i := 0; i < 20; i++ {
		op, d, a, b, c := r.number(6), r.number(4), r.number(4), r.number(4), r.number(4)
		v := meta.ExpectedVals
		names := meta.Vars
		switch op {
		case 0:
			fmt.Fprintf(&equations, "%s=~(%s&%s);", names[d], names[d], names[a])
			v[d] = ^(v[d] & v[a])
		case 1:
			fmt.Fprintf(&equations, "%s=%s^%s;", names[d], names[d], names[a])
			v[d] ^= v[a]
		case 2:
			fmt.Fprintf(&equations, "%s=%s|%s;", names[d], names[d], names[a])
			v[d] |= v[a]
		case 3:
			fmt.Fprintf(&equations, "%s=%s&%s;", names[d], names[d], names[a])
			v[d] &= v[a]
		case 4:
			fmt.Fprintf(&equations, "%s=capFnHelper(%s,%s,%s);", names[d], names[a], names[b], names[d])
			v[d] = (v[b] ^ v[a]) | (v[d] ^ v[b])
		case 5:
			fmt.Fprintf(&equations, "%s=capDomHelper(%s,%s,%s);", names[d], names[a], names[b], names[c])
			v[d] = domSum(v[a], v[b], v[c])
		}
	}
	for i := 0; i < 4; i++ {
		salt := int32(r.between(100000, 999999))
		fmt.Fprintf(&equations, "%s=((%s^%d)&0x7FFFFFFF)%%900000+100000;", meta.Vars[i], meta.Vars[i], salt)
		meta.ExpectedVals[i] = ((meta.ExpectedVals[i]^salt)&0x7fffffff)%900000 + 100000
	}
	var checks []string
	if err := json.Unmarshal(blockChecksJSON, &checks); err != nil {
		return "", Metadata{}, err
	}
	if len(checks) == 0 {
		return "", Metadata{}, errors.New("instrumentation: empty check set")
	}
	count := opts.CheckCount
	if count == 0 {
		if opts.BlockAutomatedBrowsers {
			count = len(checks) // full injection: every available check
		} else {
			count = 8 // upstream default sample (observation mode)
		}
		if count > len(checks) {
			count = len(checks)
		}
	} else if count < 1 || count > len(checks) {
		return "", Metadata{}, ErrUnsupportedCheckCount
	}
	if opts.ScopeSeed != "" {
		seededShuffle(checks, opts.ScopeSeed)
	} else {
		for i := len(checks) - 1; i > 0; i-- {
			j := r.number(i + 1)
			checks[i], checks[j] = checks[j], checks[i]
		}
	}
	if r.err != nil {
		return "", Metadata{}, r.err
	}
	// Checks are injected in every mode; BlockAutomatedBrowsers only reaches
	// Metadata and controls server-side gating of the client report.
	block := strings.Join(checks[:count], "")
	replacements := []string{"CAP_ID_PLACEHOLDER", meta.ID, "CAP_EQUATIONS_PLACEHOLDER", equations.String(), "CAP_BLOCK_CHECKS_PLACEHOLDER", block}
	for i, name := range []string{"capvarzero", "capvarone", "capvartwo", "capvarthree"} {
		replacements = append(replacements, name, meta.Vars[i], fmt.Sprint(1000000001+i), fmt.Sprint(initial[i]))
	}
	if r.err != nil {
		return "", Metadata{}, r.err
	}
	script := strings.NewReplacer(replacements...).Replace(browserTemplate)
	var err error
	script, err = randomizeTemplate(script, r)
	if err != nil {
		return "", Metadata{}, err
	}
	script, err = obfuscate(script, level, r)
	if err != nil {
		return "", Metadata{}, err
	}
	// Every interpolation is a generated identifier, integer, or fixed template;
	// no user-controlled string is interpolated into HTML/JavaScript.
	var compressed bytes.Buffer
	w, err := flate.NewWriter(&compressed, flate.BestSpeed)
	if err != nil {
		return "", Metadata{}, err
	}
	if _, err = w.Write([]byte(script)); err != nil {
		return "", Metadata{}, err
	}
	if err = w.Close(); err != nil {
		return "", Metadata{}, err
	}
	return base64.StdEncoding.EncodeToString(compressed.Bytes()), meta, nil
}

func domSum(values ...int32) int32 {
	var sum int64
	for _, v := range values {
		for i := 0; i < 8; i++ {
			if v&1 == 0 {
				sum += int64(v)
			}
			v >>= 1
		}
	}
	return int32(sum % 256)
}

// seededShuffle deterministically permutes checks from a hash stream keyed by
// scopeSeed: the same seed always yields the same permutation, so the same
// scope always faces the same check selection (for every CheckCount, since a
// smaller sample is a prefix of the same permutation). Fisher-Yates draws come
// from SHA-256(seed || counter); the modulo bias for 18 elements is below
// 2^-27 per draw and irrelevant for selection. This touches only which checks
// are injected; everything the client computes stays per-challenge random.
func seededShuffle(checks []string, scopeSeed string) {
	seed := sha256.Sum256([]byte("cap:instr-sel-v1:" + scopeSeed))
	buf := make([]byte, len(seed)+4)
	copy(buf, seed[:])
	for i := len(checks) - 1; i > 0; i-- {
		binary.BigEndian.PutUint32(buf[len(seed):], uint32(i))
		sum := sha256.Sum256(buf)
		j := int(binary.BigEndian.Uint32(sum[:4]) % uint32(i+1))
		checks[i], checks[j] = checks[j], checks[i]
	}
}
func failed(reason string) Result { return Result{Reason: reason, RiskFlags: []string{}} }

// Validate checks a decoded instrumentation result, not the outer format-1/2
// blocked/timeout envelope. Input is bounded to avoid unbounded probe decoding.
func Validate(meta Metadata, raw json.RawMessage) (Result, error) {
	if len(raw) > 64*1024 {
		return failed("missing_output"), nil
	}
	var payload map[string]json.RawMessage
	if json.Unmarshal(raw, &payload) != nil || payload == nil {
		return failed("missing_output"), nil
	}
	if meta.Expires != 0 && time.Now().UnixMilli() > meta.Expires {
		return failed("instr_expired"), nil
	}
	var id string
	if json.Unmarshal(payload["i"], &id) != nil || id != meta.ID {
		return failed("id_mismatch"), nil
	}
	var state map[string]json.RawMessage
	if json.Unmarshal(payload["state"], &state) != nil || state == nil {
		return failed("invalid_state"), nil
	}
	if len(meta.Vars) != 4 || len(meta.ExpectedVals) != 4 {
		return failed("invalid_meta"), nil
	}
	for i, v := range meta.Vars {
		n, ok := rawNumber(state[v])
		if !ok || n != float64(meta.ExpectedVals[i]) {
			return failed("failed_challenge"), nil
		}
	}
	probe := payload["p"]
	if len(probe) > 0 && string(probe) != "null" {
		var obj any
		if json.Unmarshal(probe, &obj) == nil && (object(obj) != nil || array(obj) != nil) {
			d := Detect(probe, payload["vp"])
			if meta.BlockAutomatedBrowsers && !d.Success {
				d.Reason = "instr_automated_browser"
				return d, nil
			}
			d.Success = true
			d.Reason = ""
			return d, nil
		}
	}
	if meta.BlockAutomatedBrowsers {
		return failed("instr_probe_missing"), nil
	}
	return Result{Success: true, RiskFlags: []string{}}, nil
}
func rawNumber(raw json.RawMessage) (float64, bool) {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return 0, false
	}
	return number(v)
}

package instrumentation

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

func decode(t *testing.T, s string) string {
	t.Helper()
	b, e := base64.StdEncoding.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	r := flate.NewReader(bytes.NewReader(b))
	defer r.Close()
	b, e = io.ReadAll(r)
	if e != nil {
		t.Fatal(e)
	}
	return string(b)
}
func payload(meta Metadata, p any) json.RawMessage {
	state := map[string]int32{}
	for i, v := range meta.Vars {
		state[v] = meta.ExpectedVals[i]
	}
	m := map[string]any{"i": meta.ID, "state": state}
	if p != nil {
		m["p"] = p
	}
	b, _ := json.Marshal(m)
	return b
}

// checkSection extracts the injected-checks region of a decoded script: from
// the unique "let FLAG = false;try {" opener to the flag's guarded
// postMessage (the only "if (FLAG) {parent.postMessage" in the template).
// Inner try/catch blocks of individual checks sit inside that region.
func checkSection(t *testing.T, script string) (string, string) {
	t.Helper()
	i := strings.Index(script, "false;try {")
	if i < 0 {
		t.Fatal("no injected check section")
	}
	rest := script[i:]
	m := regexp.MustCompile(`if \(!([a-z][a-z0-9]{11})`).FindStringSubmatch(rest)
	if m == nil {
		t.Fatalf("no check opener in section: %q", rest[:80])
	}
	flag := m[1]
	end := strings.Index(rest, "if ("+flag+") {parent.postMessage")
	if end < 0 {
		t.Fatal("unterminated check section")
	}
	return rest[:end], flag
}

// checkMarkers identifies each of the 18 upstream checks by a code-only
// substring (identifiers/operators, never string literals), so identification
// survives every obfuscation level. Each marker occurs in exactly one check;
// several markers also occur later in the template's probe section, which
// lies outside the extracted check section.
var checkMarkers = []string{
	"MimeTypeArray.prototype",                // navigator.mimeTypes prototypes
	".substr(i, sl)",                         // Error().stack substring scan
	"k.slice(0, pl)",                         // window-prefix loop
	"Function.prototype.toString.call(eval)", // eval native source
	"window.external.toString",               // Sequentum
	"navigator.appVersion",                   // UA token scan
	"navigator.productSub",                   // Blink productSub contradiction
	"c.RENDERER)",                            // SwiftShader webgl renderer
	"getOwnPropertyNames(document)",          // document property markers
	"window.process",                         // electron/process
	"document.hasFocus()",                    // zero-size focused window
	"documentElement.getAttributeNames()",    // selenium attribute markers
	"window.exposedFn",                       // exposeBindingHandle
	"Function.prototype.bind",                // bind existence
	"getOwnPropertyDescriptors(navigator)",   // webdriver descriptor walk
	"getOwnPropertyNames(navigator)",         // navigator property markers
	"getOwnPropertyNames(window)) { if (",    // window property markers
	"lastIndexOf(",                           // window name suffixes
}

// injectedCheckIDs returns, in script order, the marker ids of the checks the
// script injects. Two challenges are compared by which checks they inject and
// in what order, independent of renaming and obfuscation.
func injectedCheckIDs(t *testing.T, script string) []int {
	t.Helper()
	section, _ := checkSection(t, script)
	type hit struct {
		pos, id int
	}
	var hits []hit
	for id, marker := range checkMarkers {
		pos := strings.Index(section, marker)
		if pos >= 0 {
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

// deterministicRandom turns Generate fully deterministic: same stream, same
// script. Different streams model different challenges (fresh entropy).
func deterministicRandom(seed string) io.Reader {
	var buf bytes.Buffer
	for counter := 0; buf.Len() < 128*1024; counter++ {
		h := sha256.Sum256([]byte(fmt.Sprintf("%s:%d", seed, counter)))
		buf.Write(h[:])
	}
	return bytes.NewReader(buf.Bytes())
}

// Checks are injected whenever instrumentation is generated, including
// observation mode (BlockAutomatedBrowsers=false); only the sample size
// differs. Blocking defaults to the full set (18), observation to the upstream
// default (8), and explicit counts are honored exactly.
func TestCheckCountSelection(t *testing.T) {
	cases := []struct {
		opts  Options
		count int
	}{
		{Options{}, 8},
		{Options{BlockAutomatedBrowsers: true}, 18},
		{Options{CheckCount: 1}, 1},
		{Options{CheckCount: 5}, 5},
		{Options{CheckCount: 18}, 18},
		{Options{BlockAutomatedBrowsers: true, CheckCount: 5}, 5},
		{Options{BlockAutomatedBrowsers: false, CheckCount: 18}, 18},
	}
	for _, c := range cases {
		encoded, _, err := Generate(c.opts, nil)
		if err != nil {
			t.Fatalf("%+v: %v", c.opts, err)
		}
		checks := injectedCheckIDs(t, decode(t, encoded))
		if len(checks) != c.count {
			t.Fatalf("%+v injected %d checks, want %d", c.opts, len(checks), c.count)
		}
		seen := map[int]bool{}
		for _, id := range checks {
			if seen[id] {
				t.Fatalf("%+v injected check %d twice", c.opts, id)
			}
			seen[id] = true
		}
	}
	for _, count := range []int{-1, 19, 100} {
		if _, _, err := Generate(Options{CheckCount: count}, nil); !errors.Is(err, ErrUnsupportedCheckCount) {
			t.Fatalf("CheckCount %d: %v", count, err)
		}
	}
}

// A non-empty ScopeSeed makes the check selection deterministic (the same
// scope always faces the same checks, whatever the challenge entropy); an
// empty seed keeps the per-challenge random sample. A smaller CheckCount is a
// prefix of the same permutation.
func TestScopeSeedDeterministicSelection(t *testing.T) {
	seq := func(opts Options, entropy string) []int {
		t.Helper()
		encoded, _, err := Generate(opts, deterministicRandom(entropy))
		if err != nil {
			t.Fatal(err)
		}
		return injectedCheckIDs(t, decode(t, encoded))
	}
	full := Options{CheckCount: 18}
	same := func(a, b []int) bool {
		if len(a) != len(b) {
			return false
		}
		for i := range a {
			if a[i] != b[i] {
				return false
			}
		}
		return true
	}
	seeded := Options{CheckCount: 18, ScopeSeed: "client-123"}
	a := seq(seeded, "entropy-a")
	b := seq(seeded, "entropy-b")
	if !same(a, b) {
		t.Fatalf("same scope seed selected different checks across challenges: %v vs %v", a, b)
	}
	other := seq(Options{CheckCount: 18, ScopeSeed: "client-456"}, "entropy-a")
	if same(a, other) {
		t.Fatal("different scope seeds selected the same checks")
	}
	if unseededA, unseededB := seq(full, "entropy-a"), seq(full, "entropy-b"); same(unseededA, unseededB) {
		t.Fatal("empty scope seed should follow challenge entropy")
	}
	sample := seq(Options{CheckCount: 8, ScopeSeed: "client-123"}, "entropy-c")
	if !same(sample, a[:8]) {
		t.Fatalf("smaller CheckCount is not a prefix of the same seeded permutation: %v vs %v", sample, a[:8])
	}
}

// The default obfuscation level follows the mode: 6 when blocking automated
// browsers, otherwise the upstream default 3. Explicit 1..10 always wins.
func TestObfuscationDefaultFollowsBlocking(t *testing.T) {
	level := func(script string) string {
		t.Helper()
		switch {
		case !strings.Contains(script, "atob") && strings.HasPrefix(script, "//"):
			return "3"
		case strings.Contains(script, "atob") && !strings.Contains(script, "charCodeAt(0)^"):
			return "6"
		case strings.Contains(script, "charCodeAt(0)^"):
			return "7+"
		default:
			t.Fatalf("unrecognized obfuscation: %.60s", script)
			return ""
		}
	}
	obs, _, err := Generate(Options{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := level(decode(t, obs)); got != "3" {
		t.Fatalf("observation default level %s, want 3", got)
	}
	blk, _, err := Generate(Options{BlockAutomatedBrowsers: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := level(decode(t, blk)); got != "6" {
		t.Fatalf("blocking default level %s, want 6", got)
	}
	explicit, _, err := Generate(Options{BlockAutomatedBrowsers: true, ObfuscationLevel: 3}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := level(decode(t, explicit)); got != "3" {
		t.Fatalf("explicit level 3 under blocking: %s", got)
	}
	explicit7, _, err := Generate(Options{BlockAutomatedBrowsers: true, ObfuscationLevel: 7}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := level(decode(t, explicit7)); got != "7+" {
		t.Fatalf("explicit level 7 under blocking: %s", got)
	}
}
func TestGenerateValidate(t *testing.T) {
	for level := 1; level <= 10; level++ {
		encoded, meta, e := Generate(Options{ObfuscationLevel: level}, nil)
		if e != nil {
			t.Fatal(e)
		}
		s := decode(t, encoded)
		if strings.Contains(s, "PLACEHOLDER") {
			t.Fatal("unexpanded template")
		}
		if level <= 3 && (!strings.Contains(s, "fontWidths") || !strings.Contains(s, "EventTarget")) {
			t.Fatal("missing browser checks")
		}
		for _, v := range meta.ExpectedVals {
			if v < 100000 || v > 999999 {
				t.Fatal(v)
			}
		}
		r, e := Validate(meta, payload(meta, nil))
		if e != nil || !r.Success {
			t.Fatalf("%+v %v", r, e)
		}
		meta.ID = "wrong"
		r, _ = Validate(meta, payload(Metadata{ID: "original", Vars: meta.Vars, ExpectedVals: meta.ExpectedVals}, nil))
		if r.Reason != "id_mismatch" {
			t.Fatal(r)
		}
	}
}
func TestConcurrentGenerateValidate(t *testing.T) {
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, m, e := Generate(Options{}, nil)
			if e != nil {
				t.Error(e)
				return
			}
			r, e := Validate(m, payload(m, nil))
			if e != nil || !r.Success {
				t.Errorf("%+v %v", r, e)
			}
		}()
	}
	wg.Wait()
}
func TestUnsupportedLevels(t *testing.T) {
	for _, l := range []int{-1, 11, 100} {
		_, _, e := Generate(Options{ObfuscationLevel: l}, nil)
		if !errors.Is(e, ErrUnsupportedObfuscationLevel) {
			t.Fatal(l, e)
		}
	}
}
func TestRandomFailures(t *testing.T) {
	_, _, e := Generate(Options{}, strings.NewReader(""))
	if e == nil {
		t.Fatal("expected entropy failure")
	}
}
func TestValidationFailures(t *testing.T) {
	_, m, e := Generate(Options{}, nil)
	if e != nil {
		t.Fatal(e)
	}
	for _, raw := range []string{`null`, `[]`, `{}`, `{"i":null}`, `{"i":42}`, `{"i":"x","state":{}}`, strings.Repeat("x", 65537)} {
		r, _ := Validate(m, json.RawMessage(raw))
		if r.Success {
			t.Fatalf("accepted %s", raw)
		}
	}
	var body map[string]any
	json.Unmarshal(payload(m, nil), &body)
	state := body["state"].(map[string]any)
	for _, v := range []any{nil, "100000", true, 1.25, 1e99} {
		state[m.Vars[0]] = v
		b, _ := json.Marshal(body)
		r, _ := Validate(m, b)
		if r.Success {
			t.Fatal(v)
		}
	}
	m.BlockAutomatedBrowsers = true
	r, _ := Validate(m, payload(m, nil))
	if r.Reason != "instr_probe_missing" {
		t.Fatal(r)
	}
	m.Expires = time.Now().Add(-time.Minute).UnixMilli()
	r, _ = Validate(m, payload(m, nil))
	if r.Reason != "instr_expired" {
		t.Fatal(r)
	}
}
func TestUpstreamDetectionVectors(t *testing.T) {
	b, e := os.ReadFile("detect_vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	var vectors []struct {
		Probe  json.RawMessage `json:"probe"`
		Result struct {
			Pass      bool     `json:"pass"`
			BlockedBy []string `json:"blockedBy"`
			RiskFlags []string `json:"riskFlags"`
			Checks    []Check  `json:"checks"`
		} `json:"result"`
	}
	if e = json.Unmarshal(b, &vectors); e != nil {
		t.Fatal(e)
	}
	for i, v := range vectors {
		got := Detect(v.Probe, nil)
		if got.Success != v.Result.Pass || !reflect.DeepEqual(got.BlockedBy, v.Result.BlockedBy) || !reflect.DeepEqual(got.RiskFlags, v.Result.RiskFlags) {
			t.Fatalf("vector %d got %+v expected %+v", i, got, v.Result)
		}
		if len(got.Checks) != len(v.Result.Checks) {
			t.Fatalf("vector %d check count", i)
		}
		for j, c := range got.Checks {
			want := v.Result.Checks[j]
			if c.ID != want.ID || c.Passed != want.Passed || c.Gating != want.Gating {
				t.Fatalf("vector %d check %d", i, j)
			}
		}
	}
}
func TestRealBrowserInstrumentation(t *testing.T) {
	if os.Getenv("CAP_BROWSER_TEST") != "1" {
		t.Skip("set CAP_BROWSER_TEST=1 to run Chrome integration")
	}
	chrome, e := exec.LookPath("google-chrome")
	if e != nil {
		t.Skip("Chrome not installed")
	}
	// Pick, deterministically and self-adapting, a seed whose single-check
	// sample is provably benign in a genuine Chrome (headless included), so
	// the strict validation subtest never depends on which check a random
	// sample happens to include.
	benignSeed := func() string {
		var checks []string
		if json.Unmarshal(blockChecksJSON, &checks) != nil {
			t.Fatal("check set")
		}
		benign := func(body string) bool {
			for _, marker := range []string{"Function.prototype.bind", "MimeTypeArray.prototype", "Function.prototype.toString.call(eval)"} {
				if strings.Contains(body, marker) {
					return true
				}
			}
			return false
		}
		for i := 0; i < 128; i++ {
			seed := fmt.Sprintf("chrome-e2e-benign-%d", i)
			sample := append([]string(nil), checks...)
			seededShuffle(sample, seed)
			if benign(sample[0]) {
				return seed
			}
		}
		t.Fatal("no benign single-check seed found")
		return ""
	}()
	run := func(t *testing.T, opts Options) (*Metadata, map[string]json.RawMessage, bool) {
		t.Helper()
		encoded, meta, e := Generate(opts, nil)
		if e != nil {
			t.Fatal(e)
		}
		js := decode(t, encoded)
		// JSON escaping prevents the parent script's HTML parser seeing </script>.
		srcdoc := `<!doctype html><html><body><script>` + js + `</script></body></html>`
		srcJSON, _ := json.Marshal(srcdoc)
		page := fmt.Sprintf(`<!doctype html><html><body><pre id="result">waiting</pre><script>addEventListener('message',e=>{if(e.source!==document.querySelector('iframe').contentWindow)return;document.getElementById('result').textContent=JSON.stringify(e.data)});let f=document.createElement('iframe');f.sandbox='allow-scripts';f.srcdoc=%s;document.body.appendChild(f);</script></body></html>`, srcJSON)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			io.WriteString(w, page)
		}))
		defer server.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, chrome, "--headless", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage", "--no-first-run", "--user-data-dir="+t.TempDir(), "--virtual-time-budget=5000", "--dump-dom", server.URL)
		out, e := cmd.Output()
		if e != nil {
			t.Fatalf("Chrome: %v", e)
		}
		match := regexp.MustCompile(`<pre id="result">(.*?)</pre>`).FindSubmatch(out)
		if len(match) != 2 {
			t.Fatalf("no browser result %s", out)
		}
		var envelope struct {
			Type    string          `json:"type"`
			Result  json.RawMessage `json:"result"`
			Blocked bool            `json:"blocked"`
		}
		if e = json.Unmarshal([]byte(html.UnescapeString(string(match[1]))), &envelope); e != nil {
			t.Fatalf("browser did not return instrumentation: %v %s", e, match[1])
		}
		if envelope.Type != "cap:instr" {
			t.Fatal(envelope.Type)
		}
		if envelope.Blocked {
			// The injected checks ran and self-reported an automated browser.
			return &meta, nil, true
		}
		var reply map[string]json.RawMessage
		if json.Unmarshal(envelope.Result, &reply) != nil {
			t.Fatalf("browser result: %s", envelope.Result)
		}
		return &meta, reply, false
	}
	for level := 1; level <= 10; level++ {
		t.Run(fmt.Sprintf("level%d/validates", level), func(t *testing.T) {
			// One provably-benign check: a genuine browser must complete the
			// arithmetic and return a probe, which must validate in
			// observation mode.
			meta, reply, blocked := run(t, Options{ObfuscationLevel: level, CheckCount: 1, ScopeSeed: benignSeed})
			if blocked {
				t.Fatal("genuine browser tripped a benign check")
			}
			result, e := Validate(*meta, marshalReply(reply))
			if e != nil || !result.Success {
				t.Fatalf("browser validation %+v %v", result, e)
			}
			if len(reply["p"]) == 0 {
				t.Fatal("browser probe missing")
			}
		})
		t.Run(fmt.Sprintf("level%d/full-injection", level), func(t *testing.T) {
			// Full 18-check injection. Either the client self-reports blocked
			// (correct for an automated browser such as headless Chrome) or a
			// genuine browser completes and the result must validate.
			meta, reply, blocked := run(t, Options{ObfuscationLevel: level, CheckCount: 18, ScopeSeed: "chrome-e2e-full"})
			if !blocked {
				result, e := Validate(*meta, marshalReply(reply))
				if e != nil || !result.Success {
					t.Fatalf("browser validation %+v %v", result, e)
				}
				if len(reply["p"]) == 0 {
					t.Fatal("browser probe missing")
				}
			}
		})
	}
}

func marshalReply(reply map[string]json.RawMessage) json.RawMessage {
	b, _ := json.Marshal(reply)
	return b
}

func TestGeneratedArithmeticWithNode(t *testing.T) {
	node, e := exec.LookPath("node")
	if e != nil {
		t.Skip("Node is optional test oracle, never runtime dependency")
	}
	// The oracle runs the generated arithmetic (var inits + helper functions
	// + equations through the four salt lines) in a DOM-stubbed VM. Since the
	// default obfuscation level under blocking is 6, string literals (even
	// 'div') live in the pooled header, so the header is prepended and atob is
	// shimmed into the context. The injected checks sit before this slice and
	// are never executed.
	const oracle = `const fs=require('node:fs'),vm=require('node:vm');const data=JSON.parse(fs.readFileSync(0,'utf8'));let code='';const iife=data.script.indexOf('(function(){window.onload');if(iife<0)throw Error('missing iife');code+=data.script.slice(0,iife);for(const name of data.meta.vars){const re=new RegExp('var '+name+'=(-?\\d+);');const m=data.script.match(re);if(!m)throw Error('missing init');code+=m[0];}const start=data.script.indexOf('function '+data.script.match(/function (_[a-z0-9]+)\(a,b,c\)/)[1]);let pos=start;for(let i=0;i<4;i++)pos=data.script.indexOf('%900000+100000;',pos)+14;code+=data.script.slice(start,pos);class El{constructor(){this.children=[];this.style={};this.innerText='';}appendChild(c){c.parentNode=this;this.children.push(c)}removeChild(c){this.children.splice(this.children.indexOf(c),1)}get lastElementChild(){return this.children[this.children.length-1]}}const ctx={navigator:{userAgent:'browser'},document:{body:new El,createElement:()=>new El},atob:(s)=>Buffer.from(s,'base64').toString('latin1')};vm.createContext(ctx);vm.runInContext(code,ctx);console.log(JSON.stringify(data.meta.vars.map(n=>ctx[n])));`
	for i := 0; i < 100; i++ {
		encoded, m, e := Generate(Options{BlockAutomatedBrowsers: i%2 == 0}, nil)
		if e != nil {
			t.Fatal(e)
		}
		input, _ := json.Marshal(map[string]any{"script": decode(t, encoded), "meta": m})
		cmd := exec.Command(node, "-e", oracle)
		cmd.Stdin = bytes.NewReader(input)
		out, e := cmd.CombinedOutput()
		if e != nil {
			t.Fatalf("oracle %d: %v %s", i, e, out)
		}
		var vals []int32
		if e = json.Unmarshal(out, &vals); e != nil {
			t.Fatalf("%v %s", e, out)
		}
		if !reflect.DeepEqual(vals, m.ExpectedVals) {
			t.Fatalf("oracle %d got %v want %v", i, vals, m.ExpectedVals)
		}
	}
}

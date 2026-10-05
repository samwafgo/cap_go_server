package instrumentation

import (
	crand "crypto/rand"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

func TestMarkerHashKnownAnswer(t *testing.T) {
	if got := markerHash(1269424220, "[object Navigator]"); got != 965868670 {
		t.Fatal(got)
	}
	if got := markerHash(1269424220, "webdriver"); got != 2572510596 {
		t.Fatal(got)
	}
}
func TestTemplateRandomization(t *testing.T) {
	for i := 0; i < 20; i++ {
		a, _, e := Generate(Options{BlockAutomatedBrowsers: true}, nil)
		if e != nil {
			t.Fatal(e)
		}
		s := decode(t, a)
		for _, marker := range []string{"CAP_HASH_", "CAP_MARKER_", "caphelper", "capFnHelper", "capDomHelper", "PLACEHOLDER"} {
			if strings.Contains(s, marker) {
				t.Fatalf("unexpanded %s", marker)
			}
		}
	}
}
func TestObfuscationLiteralRoundtrip(t *testing.T) {
	node, e := exec.LookPath("node")
	if e != nil {
		t.Skip("optional Node oracle")
	}
	source := `// string 'in comment' must stay untouched
var result=['one',"two",'it\'s',"back\\slash",'line\nfeed','中文 🦊','</script>','',"\"quoted\"",'\x41\u0042'];var regex=/['"]/;if(!regex.test("'"))throw Error('regex changed');process.stdout.write(JSON.stringify(result));`
	expected := []string{"one", "two", "it's", "back\\slash", "line\nfeed", "中文 🦊", "</script>", "", "\"quoted\"", "AB"}
	for level := 4; level <= 10; level++ {
		generated, e := obfuscate(source, level, &randomSource{r: crand.Reader})
		if e != nil {
			t.Fatal(e)
		}
		out, e := exec.Command(node, "-e", generated).CombinedOutput()
		if e != nil {
			t.Fatalf("level%d %v %s", level, e, out)
		}
		var got []string
		if e = json.Unmarshal(out, &got); e != nil {
			t.Fatalf("%s", out)
		}
		if len(got) != len(expected) {
			t.Fatal(got)
		}
		for i := range got {
			if got[i] != expected[i] {
				t.Fatalf("level%d[%d] %q != %q", level, i, got[i], expected[i])
			}
		}
	}
}
func TestObfuscationRejectsUnsupportedGrammar(t *testing.T) {
	_, e := obfuscate("var x=`template`;", 4, &randomSource{r: crand.Reader})
	if e == nil {
		t.Fatal("expected explicit grammar error")
	}
}

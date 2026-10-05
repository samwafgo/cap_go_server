package instrumentation

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"unicode/utf16"
)

//go:embed template_params.json
var templateParamsJSON []byte

func markerHash(seed uint32, s string) uint32 {
	h := seed
	for _, c := range utf16.Encode([]rune(s)) {
		h ^= uint32(c)
		h *= 16777619
	}
	return h
}
func randomizeTemplate(script string, r *randomSource) (string, error) {
	var p struct {
		Markers     []string `json:"markers"`
		HelperCount int      `json:"helperCount"`
		EvalLocal   string   `json:"evalLocal"`
	}
	if e := json.Unmarshal(templateParamsJSON, &p); e != nil {
		return "", e
	}
	seed := uint32(r.between(1, 0x7fffffff))
	pairs := []string{"CAP_MARKER_SEED", strconv.FormatUint(uint64(seed), 10)}
	for i, m := range p.Markers {
		pairs = append(pairs, fmt.Sprintf("CAP_HASH_%05d", i), strconv.FormatUint(uint64(markerHash(seed, m)), 10))
	}
	script = strings.NewReplacer(pairs...).Replace(script)
	pairs = nil
	for i := 0; i < p.HelperCount; i++ {
		old := fmt.Sprintf("caphelper%05d", i)
		name := r.identifier()
		pairs = append(pairs, old, name)
		if old == p.EvalLocal { // Upstream reconstructs the local eval identifier from two literal pieces.
			script = strings.ReplaceAll(script, "'"+old[:2]+"'", "'"+name[:2]+"'")
			script = strings.ReplaceAll(script, "'"+old[2:]+"'", "'"+name[2:]+"'")
		}
	}
	pairs = append(pairs, "capFnHelper", "_"+r.identifier(), "capDomHelper", "_"+r.identifier())
	if r.err != nil {
		return "", r.err
	}
	return strings.NewReplacer(pairs...).Replace(script), nil
}

type literal struct {
	start, end int
	value      string
}

// stringLiterals is deliberately scoped to our generated, fixed grammar. It
// skips comments and regex literals, and rejects unsupported template literals.
// No caller-provided JavaScript is accepted.
func stringLiterals(s string) ([]literal, error) {
	out := []literal{}
	for i := 0; i < len(s); {
		if s[i] == '`' {
			return nil, fmt.Errorf("instrumentation: unexpected JS template literal")
		}
		if i+1 < len(s) && s[i] == '/' && s[i+1] == '/' {
			j := strings.IndexByte(s[i:], '\n')
			if j < 0 {
				break
			}
			i += j + 1
			continue
		}
		if i+1 < len(s) && s[i] == '/' && s[i+1] == '*' {
			j := strings.Index(s[i+2:], "*/")
			if j < 0 {
				return nil, fmt.Errorf("unterminated comment")
			}
			i += j + 4
			continue
		}
		if i+1 < len(s) && s[i] == '/' && (s[i+1] == '\\' || s[i+1] == '[' || s[i+1] == '^') {
			i++
			inClass := false
			for i < len(s) {
				if s[i] == '\\' {
					i += 2
					continue
				}
				if s[i] == '[' {
					inClass = true
				}
				if s[i] == ']' {
					inClass = false
				}
				if s[i] == '/' && !inClass {
					i++
					break
				}
				i++
			}
			continue
		}
		if s[i] != '\'' && s[i] != '"' {
			i++
			continue
		}
		start := i
		quote := s[i]
		i++
		var value strings.Builder
		for i < len(s) && s[i] != quote {
			if s[i] != '\\' {
				value.WriteByte(s[i])
				i++
				continue
			}
			i++
			if i >= len(s) {
				return nil, fmt.Errorf("unterminated escape")
			}
			switch s[i] {
			case '\\', '\'', '"', '/':
				value.WriteByte(s[i])
			case 'n':
				value.WriteByte('\n')
			case 'r':
				value.WriteByte('\r')
			case 't':
				value.WriteByte('\t')
			case 'b':
				value.WriteByte('\b')
			case 'f':
				value.WriteByte('\f')
			case 'v':
				value.WriteByte('\v')
			case '0':
				value.WriteByte(0)
			case 'x', 'u':
				n := 2
				if s[i] == 'u' {
					n = 4
				}
				if i+n >= len(s) {
					return nil, fmt.Errorf("short escape")
				}
				v, e := strconv.ParseUint(s[i+1:i+1+n], 16, 32)
				if e != nil {
					return nil, e
				}
				value.WriteRune(rune(v))
				i += n
			default:
				return nil, fmt.Errorf("unsupported escape %c", s[i])
			}
			i++
		}
		if i >= len(s) {
			return nil, fmt.Errorf("unterminated string")
		}
		i++
		out = append(out, literal{start, i, value.String()})
	}
	return out, nil
}

// obfuscate uses string-pool transformations without eval, Function, or source
// reparsing. Higher levels increase data encoding, not claimed bot resistance.
func obfuscate(script string, level int, r *randomSource) (string, error) {
	if level <= 3 {
		return script, nil
	}
	literals, e := stringLiterals(script)
	if e != nil {
		return "", e
	}
	values := []string{}
	seen := map[string]bool{}
	for _, l := range literals {
		if !seen[l.value] {
			seen[l.value] = true
			values = append(values, l.value)
		}
	}
	for i := len(values) - 1; i > 0; i-- {
		j := r.number(i + 1)
		values[i], values[j] = values[j], values[i]
	}
	indices := map[string]int{}
	for i, v := range values {
		indices[v] = i
	}
	pool := "_" + r.identifier()
	decoder := "_" + r.identifier()
	var body strings.Builder
	cursor := 0
	for _, l := range literals {
		body.WriteString(script[cursor:l.start])
		fmt.Fprintf(&body, "%s[%d]", pool, indices[l.value])
		cursor = l.end
	}
	body.WriteString(script[cursor:])
	header := ""
	switch level {
	case 4:
		b, _ := json.Marshal(values)
		header = fmt.Sprintf("var %s=%s;", pool, b)
	case 5: // Encode all strings as JSON UTF-16 escapes; no runtime decoder.
		encoded := make([]string, len(values))
		for i, v := range values {
			var b strings.Builder
			b.WriteByte('"')
			for _, c := range utf16.Encode([]rune(v)) {
				fmt.Fprintf(&b, "\\u%04x", c)
			}
			b.WriteByte('"')
			encoded[i] = b.String()
		}
		header = fmt.Sprintf("var %s=[%s];", pool, strings.Join(encoded, ","))
	case 6, 7:
		encoded := make([]string, len(values))
		for i, v := range values {
			encoded[i] = base64.StdEncoding.EncodeToString([]byte(v))
		}
		b, _ := json.Marshal(encoded)
		decode := "function(s){return decodeURIComponent(Array.prototype.map.call(atob(s),function(c){return '%'+('00'+c.charCodeAt(0).toString(16)).slice(-2)}).join(''))}"
		if level == 6 {
			header = fmt.Sprintf("var %s=%s.map(%s);", pool, b, decode)
		} else {
			key := r.between(1, 255)
			for i, v := range values {
				a := []byte(v)
				for j := range a {
					a[j] ^= byte(key)
				}
				encoded[i] = base64.StdEncoding.EncodeToString(a)
			}
			b, _ = json.Marshal(encoded)
			header = fmt.Sprintf("var %s=%s.map(function(s){return decodeURIComponent(Array.prototype.map.call(atob(s),function(c){return '%%'+('00'+(c.charCodeAt(0)^%d).toString(16)).slice(-2)}).join(''))});", pool, b, key)
		}
	default: // Per-string keys, UTF-16 XOR, with progressively finer chunks.
		entries := []any{}
		chunkSize := 0
		if level == 9 {
			chunkSize = 8
		}
		if level == 10 {
			chunkSize = 3
		}
		for _, v := range values {
			key := r.between(1, 65535)
			units := utf16.Encode([]rune(v))
			chunks := [][]uint16{}
			size := chunkSize
			if size == 0 {
				size = len(units) + 1
			}
			for start := 0; start < len(units); start += size {
				end := start + size
				if end > len(units) {
					end = len(units)
				}
				part := make([]uint16, end-start)
				for j := range part {
					part[j] = units[start+j] ^ uint16(key)
				}
				chunks = append(chunks, part)
			}
			entries = append(entries, []any{key, chunks})
		}
		b, _ := json.Marshal(entries)
		header = fmt.Sprintf("function %s(e){var s='';for(var i=0;i<e[1].length;i++){var c=e[1][i];for(var j=0;j<c.length;j++)s+=String.fromCharCode(c[j]^e[0]);}return s;}var %s=%s.map(%s);", decoder, pool, b, decoder)
	}
	if r.err != nil {
		return "", r.err
	}
	return header + body.String(), nil
}

// Adapted from Cap core/src/detect.js, Apache-2.0, pinned in NOTICE.
package instrumentation

import (
	"encoding/json"
	"math"
	"regexp"
	"sort"
	"strings"
)

var mobileUA = regexp.MustCompile(`(?i)Android|iPhone|iPad|iPod|IEMobile|BlackBerry|Mobile Safari|; Mobile|Silk|Kindle|Tizen|Opera Mini`)

func number(v any) (float64, bool) {
	n, ok := v.(float64)
	return n, ok && !math.IsNaN(n) && !math.IsInf(n, 0)
}
func object(v any) map[string]any { m, _ := v.(map[string]any); return m }
func array(v any) []any           { a, _ := v.([]any); return a }
func text(v any) string           { s, _ := v.(string); return s }
func truth(v any) bool            { b, _ := v.(bool); return b }
func isFalse(v any) bool          { b, ok := v.(bool); return ok && !b }
func at(a []any, i int) any {
	if i >= len(a) {
		return nil
	}
	return a[i]
}
func typeOK(v any, exists bool, kind string) bool {
	if !exists {
		return false
	}
	switch kind {
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "object":
		return object(v) != nil
	case "array":
		return array(v) != nil
	case "nullableObject":
		return v == nil || object(v) != nil
	case "nullableBoolean":
		_, ok := v.(bool)
		return v == nil || ok
	}
	return false
}

// Detect evaluates the upstream gating checks and non-gating risk signals.
// The optional viewport is the parent widget's [innerWidth,innerHeight].
// Result.Success is the detector's pass flag; native_tamper never gates.
func Detect(probe json.RawMessage, viewport json.RawMessage) Result {
	result := Result{Success: true, RiskFlags: []string{}, BlockedBy: []string{}, Checks: []Check{}}
	var decoded any
	if len(probe) > 64*1024 || json.Unmarshal(probe, &decoded) != nil || decoded == nil || (object(decoded) == nil && array(decoded) == nil) {
		result.Success = false
		result.BlockedBy = []string{"probe_missing"}
		return result
	}
	isArray := array(decoded) != nil
	s := object(decoded)
	if s == nil {
		s = map[string]any{}
	}
	var vp []any
	if json.Unmarshal(viewport, &vp) == nil && len(vp) == 2 {
		s["innerWH"] = vp
	}
	add := func(id string, pass bool, detail string, gating bool) {
		result.Checks = append(result.Checks, Check{ID: id, Passed: pass, Detail: detail, Gating: gating})
		if !pass {
			if gating {
				result.Success = false
				result.BlockedBy = append(result.BlockedBy, id)
			} else {
				result.RiskFlags = append(result.RiskFlags, id)
			}
		}
	}
	fields := [][2]string{{"ua", "string"}, {"productSub", "string"}, {"oscpu", "string"}, {"uaDataPresent", "boolean"}, {"uaData", "nullableObject"}, {"plugins", "object"}, {"engine", "object"}, {"screen", "object"}, {"outerWH", "array"}, {"isExtended", "nullableBoolean"}, {"fontWidths", "array"}, {"tamper", "nullableObject"}}
	bad := []string{}
	for _, field := range fields {
		v, exists := s[field[0]]
		if !typeOK(v, exists, field[1]) {
			bad = append(bad, field[0])
		}
	}
	if isArray {
		bad = []string{"probe"}
	}
	widths := array(s["fontWidths"])
	if widths != nil && len(widths) != 17 {
		bad = append(bad, "fontWidths.length")
	}
	detail := "all fields present"
	if len(bad) > 0 {
		n := len(bad)
		if n > 6 {
			n = 6
		}
		detail = "missing or malformed: " + strings.Join(bad[:n], ", ")
	}
	add("probe_incomplete", len(bad) == 0, detail, true)
	engine := object(s["engine"])
	uaData := object(s["uaData"])
	oscpu, oscpuIsString := s["oscpu"].(string)
	gecko := truth(engine["hasMozInnerScreenX"]) || (text(s["productSub"]) == "20100101" && isFalse(s["uaDataPresent"])) || (oscpuIsString && oscpu != "__undefined")
	chromium := truth(s["uaDataPresent"]) || truth(engine["hasChrome"])
	mobile := truth(uaData["mobile"]) || mobileUA.MatchString(text(s["ua"]))
	count, n := 0, 0
	distinct := map[float64]bool{}
	for i, v := range widths {
		if i >= 64 {
			break
		}
		x, ok := number(v)
		if !ok {
			continue
		}
		n++
		if math.Trunc(x) == x {
			count++
			distinct[x] = true
		}
	}
	quantized := n >= 6 && count >= 5 && len(distinct) >= 3
	add("geometry_quantized", !quantized, "", true)
	add("webdriver_true", !truth(s["webdriver"]), "", true)
	_, hasWebdriver := s["webdriver"]
	add("webdriver_stripped", !(chromium && !hasWebdriver), "", true)
	_, hasMemory := number(s["deviceMemory"])
	add("gecko_contradiction", !(gecko && (hasMemory || truth(s["uaDataPresent"]))), "", true)
	screen := object(s["screen"])
	outer := array(s["outerWH"])
	inner := array(s["innerWH"])
	oh, okOH := number(at(outer, 1))
	sh, okSH := number(screen["height"])
	add("window_exceeds_screen", !(okOH && okSH && oh > sh+16 && isFalse(s["isExtended"])), "", true)
	iw, okIW := number(at(inner, 0))
	ih, okIH := number(at(inner, 1))
	sw, okSW := number(screen["width"])
	override := !mobile && okIW && okIH && okSW && okSH && iw == sw && ih == sh && okOH && oh > ih
	add("viewport_override", !override, "", true)
	brands := []string{}
	for _, b := range array(uaData["brands"]) {
		brands = append(brands, text(b))
	}
	headless := strings.Contains(strings.ToLower(strings.Join(brands, " ")), "headlesschrome") || strings.Contains(strings.ToLower(text(s["ua"])), "headlesschrome")
	add("headless_token", !headless, "", true)
	tampered := []string{}
	for k, v := range object(s["tamper"]) {
		if isFalse(v) {
			tampered = append(tampered, k)
		}
	}
	sort.Strings(tampered)
	detail = "native"
	if len(tampered) > 0 {
		if len(tampered) > 8 {
			tampered = tampered[:8]
		}
		for i, k := range tampered {
			runes := []rune(k)
			if len(runes) > 32 {
				tampered[i] = string(runes[:32])
			}
		}
		detail = "JS-overridden: " + strings.Join(tampered, ", ")
	}
	add("native_tamper", len(tampered) == 0, detail, false)
	return result
}

// Modified protocol port of @cap.js/core 0.1.3, pinned in MODERN_PROTOCOL.md.
// Upstream Copyright 2025 Tiago, Apache-2.0; see MODERN_LICENSE.
package capserver

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"strings"
)

const modernJWTHeader = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
const maxSafeNonce uint64 = 9007199254740991

func modernMAC(secret []byte, s string) []byte {
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(s))
	return h.Sum(nil)
}
func modernRandomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
func modernSign(v any, secret []byte) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	s := modernJWTHeader + "." + base64.RawURLEncoding.EncodeToString(b)
	return s + "." + base64.RawURLEncoding.EncodeToString(modernMAC(secret, s)), nil
}
func modernVerify(token string, secret []byte, out any) bool {
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[0] != modernJWTHeader {
		return false
	}
	sig, err := base64.RawURLEncoding.Strict().DecodeString(parts[2])
	if err != nil || !hmac.Equal(sig, modernMAC(secret, parts[0]+"."+parts[1])) {
		return false
	}
	b, err := base64.RawURLEncoding.Strict().DecodeString(parts[1])
	if err != nil {
		return false
	}
	return json.Unmarshal(b, out) == nil
}
func modernGCM(secret []byte, info string) (cipher.AEAD, error) {
	block, err := aes.NewCipher(modernMAC(secret, info))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
func modernEncrypt(v any, secret []byte, info string) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	a, err := modernGCM(secret, info)
	if err != nil {
		return "", err
	}
	iv := make([]byte, a.NonceSize())
	if _, err = rand.Read(iv); err != nil {
		return "", err
	}
	sealed := a.Seal(nil, iv, b, nil)
	// Node wire order is IV (12), authentication tag (16), ciphertext.
	out := append(iv, sealed[len(sealed)-a.Overhead():]...)
	out = append(out, sealed[:len(sealed)-a.Overhead()]...)
	return base64.RawURLEncoding.EncodeToString(out), nil
}
func modernDecrypt(s string, secret []byte, info string, out any) bool {
	b, err := base64.RawURLEncoding.Strict().DecodeString(s)
	if err != nil || len(b) < 28 {
		return false
	}
	a, err := modernGCM(secret, info)
	if err != nil {
		return false
	}
	sealed := append(append([]byte(nil), b[28:]...), b[12:28]...)
	plain, err := a.Open(nil, b[:12], sealed, nil)
	return err == nil && json.Unmarshal(plain, out) == nil
}
func modernFNV(state uint32, s string) uint32 {
	for i := 0; i < len(s); i++ {
		state ^= uint32(s[i])
		state *= 16777619
	}
	return state
}
func modernPRNG(state uint32, n int) string {
	var b strings.Builder
	for b.Len() < n {
		state ^= state << 13
		state ^= state >> 17
		state ^= state << 5
		v := strconv.FormatUint(uint64(state), 16)
		b.WriteString(strings.Repeat("0", 8-len(v)))
		b.WriteString(v)
	}
	return b.String()[:n]
}
func modernSHAValid(salt, nonce, target string) bool {
	if len(target) < 1 || len(target) > 16 {
		return false
	}
	h := sha256.Sum256([]byte(salt + nonce))
	return strings.HasPrefix(hex.EncodeToString(h[:]), target)
}

// parseModernNonce rejects JS precision loss, negatives, fractions, exponent
// notation and unbounded strings. Strings are allowed only in format 2.
// Leading zeroes are retained for SHA256, as JS hashes their exact string form.
func parseModernNonce(raw json.RawMessage, allowString bool) (string, uint64, bool) {
	if len(raw) == 0 || len(raw) > 22 {
		return "", 0, false
	}
	s := string(raw)
	quoted := s[0] == '"'
	if quoted {
		if !allowString || json.Unmarshal(raw, &s) != nil {
			return "", 0, false
		}
	}
	if len(s) < 1 || len(s) > 20 {
		return "", 0, false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return "", 0, false
		}
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || (!quoted && n > maxSafeNonce) {
		return "", 0, false
	}
	return s, n, true
}

var ErrInvalidOptions = errors.New("cap: invalid challenge options")
var ErrInvalidScope = errors.New("cap: scope must contain 1..4096 bytes")

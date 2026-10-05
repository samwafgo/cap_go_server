// Modified pure-Go port of core/src/rsw.js, @cap.js/core 0.1.3.
// Upstream Copyright 2025 Tiago, Apache-2.0; see MODERN_LICENSE.
package capserver

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
)

// RSWKeypair uses decimal strings and the upstream serialized key shape.
// P and Q are secret trapdoors: store securely, never send them to clients.
type RSWKeypair struct {
	N    string `json:"N"`
	P    string `json:"p"`
	Q    string `json:"q"`
	Bits int    `json:"bits"`
}

func GenerateRSWKeypair() (*RSWKeypair, error) {
	p, err := rand.Prime(rand.Reader, 1024)
	if err != nil {
		return nil, err
	}
	var q *big.Int
	for {
		q, err = rand.Prime(rand.Reader, 1024)
		if err != nil {
			return nil, err
		}
		if p.Cmp(q) != 0 {
			break
		}
	}
	n := new(big.Int).Mul(p, q)
	return &RSWKeypair{N: n.String(), P: p.String(), Q: q.String(), Bits: 2048}, nil
}

type rswMinter struct {
	n, p, q, pm1, qm1, gp, gq, hp, hq, qinv *big.Int
	t                                       int
	nhex                                    string
	width                                   int
}

func parseRSWKey(k *RSWKeypair) (n, p, q *big.Int, err error) {
	bad := errors.New("cap: invalid RSW key; require distinct 1024-bit primes and 2048-bit product")
	if k == nil || len(k.N) > 617 || len(k.P) > 309 || len(k.Q) > 309 {
		return nil, nil, nil, bad
	}
	n, ok := new(big.Int).SetString(k.N, 10)
	if !ok {
		return nil, nil, nil, bad
	}
	p, ok = new(big.Int).SetString(k.P, 10)
	if !ok {
		return nil, nil, nil, bad
	}
	q, ok = new(big.Int).SetString(k.Q, 10)
	if !ok {
		return nil, nil, nil, bad
	}
	if (k.Bits != 0 && k.Bits != 2048) || n.BitLen() != 2048 || p.BitLen() != 1024 || q.BitLen() != 1024 || p.Cmp(q) == 0 || new(big.Int).Mul(p, q).Cmp(n) != 0 || !p.ProbablyPrime(32) || !q.ProbablyPrime(32) {
		return nil, nil, nil, bad
	}
	return n, p, q, nil
}
func newRSWMinter(k *RSWKeypair, t int) (*rswMinter, error) {
	n, p, q, err := parseRSWKey(k)
	if err != nil {
		return nil, err
	}
	return newRSWMinterParsed(n, p, q, t)
}
func newRSWMinterParsed(n, p, q *big.Int, t int) (*rswMinter, error) {
	if t < 1 || t > 10000000 {
		return nil, errors.New("cap: RSW t must be in [1,10000000]")
	}
	one := big.NewInt(1)
	pm1 := new(big.Int).Sub(p, one)
	qm1 := new(big.Int).Sub(q, one)
	var g *big.Int
	for {
		v, err := rand.Int(rand.Reader, new(big.Int).Sub(n, big.NewInt(3)))
		if err != nil {
			return nil, err
		}
		g = new(big.Int).Add(v, big.NewInt(2))
		if new(big.Int).GCD(nil, nil, g, n).Cmp(one) == 0 {
			break
		}
	}
	ep := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(t)), pm1)
	eq := new(big.Int).Exp(big.NewInt(2), big.NewInt(int64(t)), qm1)
	gp := new(big.Int).Mod(g, p)
	gq := new(big.Int).Mod(g, q)
	return &rswMinter{n: n, p: p, q: q, pm1: pm1, qm1: qm1, gp: gp, gq: gq, hp: new(big.Int).Exp(gp, ep, p), hq: new(big.Int).Exp(gq, eq, q), qinv: new(big.Int).ModInverse(q, p), t: t, nhex: n.Text(16), width: 512}, nil
}
func (m *rswMinter) crt(a, b *big.Int) *big.Int {
	s := new(big.Int).Sub(a, b)
	s.Mul(s, m.qinv)
	s.Mod(s, m.p)
	s.Mul(s, m.q)
	return s.Add(s, b)
}
func (m *rswMinter) mint() (string, string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", err
	}
	r := new(big.Int).SetBytes(buf)
	rp := new(big.Int).Mod(r, m.pm1)
	rq := new(big.Int).Mod(r, m.qm1)
	x := m.crt(new(big.Int).Exp(m.gp, rp, m.p), new(big.Int).Exp(m.gq, rq, m.q))
	y := m.crt(new(big.Int).Exp(m.hp, rp, m.p), new(big.Int).Exp(m.hq, rq, m.q))
	pad := func(v *big.Int) string { s := v.Text(16); return strings.Repeat("0", m.width-len(s)) + s }
	return pad(x), pad(y), nil
}
func verifyRSW(expected, claimed string) bool {
	if strings.HasPrefix(claimed, "0x") {
		claimed = claimed[2:]
	}
	if len(claimed) == 0 || len(claimed) > 512 {
		return false
	}
	// Bounded, strictly hexadecimal, accepting upper-case and omitted leading zeroes.
	if len(claimed)%2 != 0 {
		claimed = "0" + claimed
	}
	b, err := hex.DecodeString(claimed)
	if err != nil {
		return false
	}
	e, err := hex.DecodeString(expected)
	if err != nil || len(e) != 256 {
		return false
	}
	padded := make([]byte, 256)
	copy(padded[256-len(b):], b)
	return subtle.ConstantTimeCompare(e, padded) == 1
}

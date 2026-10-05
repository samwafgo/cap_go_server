package capserver

import (
	"math/big"
	"strings"
	"testing"
)

func TestRSWTrapdoorAndKeyValidation(t *testing.T) {
	key, err := GenerateRSWKeypair()
	if err != nil {
		t.Fatal(err)
	}
	m, err := newRSWMinter(key, 97)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		x, y, err := m.mint()
		if err != nil {
			t.Fatal(err)
		}
		value, _ := new(big.Int).SetString(x, 16)
		for j := 0; j < m.t; j++ {
			value.Mul(value, value)
			value.Mod(value, m.n)
		}
		if !verifyRSW(y, value.Text(16)) || !verifyRSW(y, "0x"+strings.ToUpper(value.Text(16))) {
			t.Fatal("trapdoor differs from repeated squaring")
		}
		if verifyRSW(y, strings.Repeat("0", 513)) || verifyRSW(y, "xyz") || verifyRSW(y, "-1") {
			t.Fatal("malformed accepted")
		}
	}
	bad := *key
	bad.Q = bad.P
	if _, err = newRSWMinter(&bad, 1); err == nil {
		t.Fatal("repeated factor accepted")
	}
	bad = *key
	bad.N = "1"
	if _, err = newRSWMinter(&bad, 1); err == nil {
		t.Fatal("wrong modulus accepted")
	}
	bad = *key
	bad.P = strings.Repeat("9", 310)
	if _, err = newRSWMinter(&bad, 1); err == nil {
		t.Fatal("oversized factor accepted")
	}
	if _, err = newRSWMinter(key, 0); err == nil {
		t.Fatal("zero t accepted")
	}
}

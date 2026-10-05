package hashwx

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestSpecificationVectors(t *testing.T) {
	for _, tc := range []struct {
		seed        string
		nonce, want uint64
	}{
		{"5468697320697320612074657374207365656420666f72206861736877780000", 0, 0x973684176f8ee362},
		{"5468697320697320612074657374207365656420666f72206861736877780000", 123456, 0x401983bb07d69b07},
		{"4c6f72656d20697073756d20646f6c6f722073697420616d6574000000000000", 123456, 0x4af38d834a9a8d3d},
		{"4c6f72656d20697073756d20646f6c6f722073697420616d6574000000000000", 987654321123456789, 0x6a8a5514432e17a3},
	} {
		seed, err := hex.DecodeString(tc.seed)
		if err != nil {
			t.Fatal(err)
		}
		got, err := Hash(seed, tc.nonce)
		if err != nil {
			t.Fatal(err)
		}
		if got != tc.want {
			t.Errorf("seed=%s nonce=%d: got %016x, want %016x", tc.seed, tc.nonce, got, tc.want)
		}
	}
}

func TestSeedLength(t *testing.T) {
	for _, n := range []int{0, 1, 16, 31, 33, 64, 1024} {
		if p, err := New(make([]byte, n)); p != nil || !errors.Is(err, ErrSeedSize) {
			t.Errorf("length %d: got %v, %v", n, p, err)
		}
		if got, err := Hash(make([]byte, n), 0); got != 0 || !errors.Is(err, ErrSeedSize) {
			t.Errorf("Hash length %d: got %x, %v", n, got, err)
		}
	}
}

func TestUninitializedProgram(t *testing.T) {
	for _, p := range []*Program{nil, new(Program)} {
		func() {
			defer func() {
				if recover() == nil {
					t.Error("expected panic for uninitialized Program")
				}
			}()
			p.Hash(0)
		}()
	}
}

func TestSeedOwnershipAndConcurrentHash(t *testing.T) {
	seed := make([]byte, SeedSize)
	p, err := New(seed)
	if err != nil {
		t.Fatal(err)
	}
	var want [64]uint64
	for i := range want {
		want[i] = p.Hash(uint64(i))
	}
	for i := range seed {
		seed[i] = 0xff
	}
	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i, expected := range want {
				if got := p.Hash(uint64(i)); got != expected {
					t.Errorf("nonce=%d: got %x want %x", i, got, expected)
				}
			}
		}()
	}
	wg.Wait()
}

type oracleCase struct {
	Seed  string `json:"seed"`
	Nonce string `json:"nonce"`
	Hash  string `json:"hash"`
}

func checkOracleCases(t *testing.T, cases []oracleCase) {
	t.Helper()
	programs := make(map[string]*Program)
	for _, tc := range cases {
		p := programs[tc.Seed]
		if p == nil {
			seed, err := hex.DecodeString(tc.Seed)
			if err != nil {
				t.Fatal(err)
			}
			p, err = New(seed)
			if err != nil {
				t.Fatal(err)
			}
			programs[tc.Seed] = p
		}
		nonce, err := strconv.ParseUint(tc.Nonce, 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		want, err := strconv.ParseUint(tc.Hash, 16, 64)
		if err != nil {
			t.Fatal(err)
		}
		if got := p.Hash(nonce); got != want {
			t.Fatalf("seed=%s nonce=%d: got %016x want %016x", tc.Seed, nonce, got, want)
		}
	}
	t.Logf("matched %d oracle cases across %d seeds", len(cases), len(programs))
}

func TestNodeOracleFixtures(t *testing.T) {
	data, err := os.ReadFile("testdata/cap-oracle.json")
	if err != nil {
		t.Fatal(err)
	}
	var cases []oracleCase
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	if len(cases) != 1024 {
		t.Fatalf("fixture count: got %d want 1024", len(cases))
	}
	checkOracleCases(t, cases)
}

// Set HASHWX_CAP_ORACLE to the pinned Cap checkout's core/src/hashwx.js to
// run fresh differential tests. The checked-in fixtures run without Node.
func TestNodeDifferential(t *testing.T) {
	if os.Getenv("HASHWX_CAP_ORACLE") == "" {
		t.Skip("set HASHWX_CAP_ORACLE to run the live Node differential oracle")
	}
	if _, err := exec.LookPath("node"); err != nil {
		t.Fatal(err)
	}
	random := rand.New(rand.NewSource(0x484153485758))
	cases := make([]oracleCase, 512)
	for i := range cases {
		seed := make([]byte, SeedSize)
		if _, err := random.Read(seed); err != nil {
			t.Fatal(err)
		}
		cases[i] = oracleCase{Seed: hex.EncodeToString(seed), Nonce: strconv.FormatUint(random.Uint64(), 10)}
	}
	data, err := json.Marshal(cases)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "node", "testdata/oracle.mjs")
	cmd.Stdin = bytes.NewReader(data)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("Node oracle: %v\n%s", err, stderr.String())
	}
	var actual []oracleCase
	if err := json.Unmarshal(output, &actual); err != nil {
		t.Fatal(err)
	}
	if len(actual) != len(cases) {
		t.Fatalf("oracle returned %d cases, want %d", len(actual), len(cases))
	}
	for i := range cases {
		if actual[i].Seed != cases[i].Seed || actual[i].Nonce != cases[i].Nonce {
			t.Fatalf("oracle changed input %d", i)
		}
	}
	checkOracleCases(t, actual)
}

func BenchmarkHash(b *testing.B) {
	p, err := New(make([]byte, SeedSize))
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		p.Hash(uint64(i))
	}
}

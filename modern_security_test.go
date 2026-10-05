package capserver

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestModernSharedStoreAndRestart(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryStore(100)
	first := testEngine(t, store)
	c, err := first.GenerateChallenge(ctx, "scope", Options{ChallengeCount: 1, ChallengeDifficulty: 1})
	if err != nil {
		t.Fatal(err)
	}
	body := solveModernV1(t, c)
	restarted := testEngine(t, store)
	r, err := restarted.Redeem(ctx, "scope", body)
	if err != nil || !r.Success {
		t.Fatal(r, err)
	}
	replay, err := first.Redeem(ctx, "scope", body)
	if err != nil || replay.Reason != "already_redeemed" {
		t.Fatal(replay, err)
	}
	ok, err := first.ValidateToken(ctx, "scope", r.Token)
	if err != nil || !ok {
		t.Fatal(ok, err)
	}
}

type tokenFailStore struct{ Store }

func (s tokenFailStore) PutIfAbsent(ctx context.Context, key string, value []byte, exp time.Time) (bool, error) {
	if strings.Contains(key, ":token:") {
		return false, errors.New("token store offline")
	}
	return s.Store.PutIfAbsent(ctx, key, value, exp)
}
func TestModernTokenWriteFailureDoesNotRollbackNonce(t *testing.T) {
	ctx := context.Background()
	e := testEngine(t, tokenFailStore{NewMemoryStore(100)})
	c, _ := e.GenerateChallenge(ctx, "scope", Options{ChallengeCount: 1, ChallengeDifficulty: 1})
	body := solveModernV1(t, c)
	r, err := e.Redeem(ctx, "scope", body)
	if err == nil || r.Success || r.Reason != "token_store_error" {
		t.Fatal(r, err)
	}
	r, err = e.Redeem(ctx, "scope", body)
	if err != nil || r.Reason != "already_redeemed" {
		t.Fatal(r, err)
	}
}
func TestModernV2AllValidationPrecedesNonce(t *testing.T) {
	ctx := context.Background()
	e := testEngine(t, nil)
	c, err := e.GenerateChallenge(ctx, "scope", Options{Format: 2, Protocols: []string{"hashwx", "instrumentation"}, HashWXDifficulty: 1, HashWXChallengeCount: 1})
	if err != nil {
		t.Fatal(err)
	}
	var claims modernClaims
	if !modernVerify(c.Token, e.secret, &claims) {
		t.Fatal("JWT")
	}
	var env modernExpectedEnvelope
	if !modernDecrypt(claims.EV, e.secret, "cap:fmt2-v1", &env) {
		t.Fatal("GCM")
	}
	meta := env.Expected[1].InstrMeta
	state := map[string]int32{}
	for i, v := range meta.Vars {
		state[v] = meta.ExpectedVals[i]
	}
	sol := []any{map[string]any{"nonce": "18446744073709551615"}, map[string]any{"timeout": true}}
	raw, _ := json.Marshal(map[string]any{"token": c.Token, "solutions": sol})
	r, err := e.Redeem(ctx, "scope", raw)
	if err != nil || r.Reason != "instr_timeout" || !r.InstrError {
		t.Fatal(r, err)
	}
	sol[1] = map[string]any{"instr": map[string]any{"i": meta.ID, "state": state}}
	raw, _ = json.Marshal(map[string]any{"token": c.Token, "solutions": sol})
	r, err = e.Redeem(ctx, "scope", raw)
	if err != nil || !r.Success {
		t.Fatal(r, err)
	}
}

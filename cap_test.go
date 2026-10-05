package capserver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	// Test with nil config
	cap := New(nil)
	if cap == nil {
		t.Fatal("Expected non-nil Cap instance")
	}
	if cap.config.TokensStorePath != DefaultTokensStore {
		t.Errorf("Expected default tokens store path %s, got %s", DefaultTokensStore, cap.config.TokensStorePath)
	}
	if cap.fsEnabled {
		t.Error("Expected file persistence to be disabled by default")
	}

	// Test with custom config
	customConfig := &CapConfig{
		TokensStorePath: "./test_tokens.json",
		NoFSState:       true,
	}
	cap2 := New(customConfig)
	if cap2.config.TokensStorePath != "./test_tokens.json" {
		t.Errorf("Expected custom tokens store path ./test_tokens.json, got %s", cap2.config.TokensStorePath)
	}
	if !cap2.config.NoFSState {
		t.Error("Expected NoFSState to be true")
	}
	if cap2.fsEnabled {
		t.Error("Expected file persistence to stay disabled when NoFSState is set")
	}

	// EnableFSState opts in, NoFSState still wins for backward compatibility
	cap3 := New(&CapConfig{TokensStorePath: "./test_tokens.json", EnableFSState: true})
	if !cap3.fsEnabled {
		t.Error("Expected file persistence to be enabled by EnableFSState")
	}
	cap4 := New(&CapConfig{TokensStorePath: "./test_tokens.json", EnableFSState: true, NoFSState: true})
	if cap4.fsEnabled {
		t.Error("Expected NoFSState to override EnableFSState")
	}

	// State with nil maps must not panic on use
	cap5 := New(&CapConfig{State: &ChallengeState{}})
	if _, err := cap5.CreateChallenge(&ChallengeConfig{ChallengeCount: 1, Store: true}); err != nil {
		t.Fatalf("Failed to create challenge with empty state: %v", err)
	}
}

// TestNewCreatesNoFilesByDefault guards the regression where New() eagerly
// created a .data/tokensList.json under the process working directory.
func TestNewCreatesNoFilesByDefault(t *testing.T) {
	tmpDir := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Failed to get working directory: %v", err)
	}
	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("Failed to change working directory: %v", err)
	}
	defer os.Chdir(origDir)

	// Both the default config and the pre-v1.0.1 "NoFSState: false" spelling
	// must leave the working directory untouched.
	New(nil)
	New(&CapConfig{NoFSState: false})

	entries, err := os.ReadDir(tmpDir)
	if err != nil {
		t.Fatalf("Failed to read temp dir: %v", err)
	}
	if len(entries) != 0 {
		names := make([]string, 0, len(entries))
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Errorf("Expected no files to be created, got %v", names)
	}
}

// TestNoEagerFileCreationWhenEnabled checks that even with persistence enabled
// nothing is written until there is an actual token to store.
func TestNoEagerFileCreationWhenEnabled(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "nested", "tokensList.json")

	cap := New(&CapConfig{TokensStorePath: storePath, EnableFSState: true})

	if _, err := os.Stat(filepath.Dir(storePath)); !os.IsNotExist(err) {
		t.Error("Expected tokens directory not to be created on New()")
	}

	cap.mu.Lock()
	cap.config.State.TokensList["k"] = time.Now().UnixMilli() + 60000
	cap.persist()
	cap.mu.Unlock()

	if _, err := os.Stat(storePath); err != nil {
		t.Errorf("Expected tokens file after the first write, got %v", err)
	}
}

// TestSaveTokensIsAtomic verifies the temporary file is renamed into place and
// never left behind.
func TestSaveTokensIsAtomic(t *testing.T) {
	dir := t.TempDir()
	storePath := filepath.Join(dir, "tokensList.json")

	cap := New(&CapConfig{TokensStorePath: storePath, EnableFSState: true, SaveThrottleMs: -1})
	cap.config.State.TokensList["test"] = time.Now().UnixMilli() + 60000
	if err := cap.saveTokens(); err != nil {
		t.Fatalf("Failed to save tokens: %v", err)
	}

	if _, err := os.Stat(storePath + ".tmp"); !os.IsNotExist(err) {
		t.Error("Expected no leftover .tmp file")
	}

	data, err := os.ReadFile(storePath)
	if err != nil {
		t.Fatalf("Failed to read tokens file: %v", err)
	}
	var loaded map[string]int64
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("Tokens file is not valid JSON: %v", err)
	}
	if _, exists := loaded["test"]; !exists {
		t.Error("Expected the token to be present in the file")
	}
}

// TestSaveThrottle checks that writes within the throttle window are coalesced
// and that Flush() still gets them to disk.
func TestSaveThrottle(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "tokensList.json")

	cap := New(&CapConfig{TokensStorePath: storePath, EnableFSState: true, SaveThrottleMs: 60000})

	cap.mu.Lock()
	cap.config.State.TokensList["a"] = time.Now().UnixMilli() + 60000
	cap.persist() // first write always goes through
	cap.config.State.TokensList["b"] = time.Now().UnixMilli() + 60000
	cap.persist() // throttled
	dirty := cap.dirty
	cap.mu.Unlock()

	if !dirty {
		t.Error("Expected the throttled change to be marked dirty")
	}

	data, _ := os.ReadFile(storePath)
	var loaded map[string]int64
	json.Unmarshal(data, &loaded)
	if _, exists := loaded["b"]; exists {
		t.Error("Expected the second change to be coalesced, not written")
	}

	if err := cap.Flush(); err != nil {
		t.Fatalf("Flush failed: %v", err)
	}
	data, _ = os.ReadFile(storePath)
	loaded = nil
	json.Unmarshal(data, &loaded)
	if _, exists := loaded["b"]; !exists {
		t.Error("Expected Flush to write the pending change")
	}
}

// TestLoadTokensBadInput makes sure a missing, empty or corrupt file degrades
// to an empty state instead of panicking.
func TestLoadTokensBadInput(t *testing.T) {
	dir := t.TempDir()

	for name, content := range map[string]string{
		"corrupt.json": "not json at all",
		"null.json":    "null",
		"empty.json":   "",
	} {
		storePath := filepath.Join(dir, name)
		if err := os.WriteFile(storePath, []byte(content), 0600); err != nil {
			t.Fatalf("Failed to write %s: %v", name, err)
		}

		cap := New(&CapConfig{TokensStorePath: storePath, EnableFSState: true})
		if cap.config.State.TokensList == nil {
			t.Fatalf("%s: expected non-nil tokens list", name)
		}
		if len(cap.config.State.TokensList) != 0 {
			t.Errorf("%s: expected empty tokens list, got %d entries", name, len(cap.config.State.TokensList))
		}
		// Must not panic when writing into the recovered state.
		cap.config.State.TokensList["k"] = time.Now().UnixMilli() + 60000
	}
}

// TestSilentByDefault makes sure diagnostics only surface through an injected
// logger.
func TestSilentByDefault(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "corrupt.json")
	if err := os.WriteFile(storePath, []byte("{oops"), 0600); err != nil {
		t.Fatalf("Failed to write file: %v", err)
	}

	var logged []string
	New(&CapConfig{
		TokensStorePath: storePath,
		EnableFSState:   true,
		Logger: func(format string, args ...interface{}) {
			logged = append(logged, fmt.Sprintf(format, args...))
		},
	})

	if len(logged) == 0 {
		t.Error("Expected the injected logger to receive the parse failure")
	}
}

func TestCreateChallenge(t *testing.T) {
	cap := New(&CapConfig{NoFSState: true})

	// Test with default config
	challenge, err := cap.CreateChallenge(nil)
	if err != nil {
		t.Fatalf("Failed to create challenge: %v", err)
	}
	if len(challenge.Challenge) != DefaultChallengeCount {
		t.Errorf("Expected %d challenges, got %d", DefaultChallengeCount, len(challenge.Challenge))
	}
	if challenge.Token == "" {
		t.Error("Expected non-empty token")
	}
	if challenge.Expires <= time.Now().UnixMilli() {
		t.Error("Expected future expiration time")
	}

	// Test with custom config
	customConfig := &ChallengeConfig{
		ChallengeCount:      10,
		ChallengeSize:       16,
		ChallengeDifficulty: 2,
		ExpiresMs:           30000,
		Store:               true,
	}
	customChallenge, err := cap.CreateChallenge(customConfig)
	if err != nil {
		t.Fatalf("Failed to create custom challenge: %v", err)
	}
	if len(customChallenge.Challenge) != 10 {
		t.Errorf("Expected 10 challenges, got %d", len(customChallenge.Challenge))
	}

	// Verify challenge structure
	for i, ch := range customChallenge.Challenge {
		if len(ch[0]) != 16 {
			t.Errorf("Challenge %d: expected salt length 16, got %d", i, len(ch[0]))
		}
		if len(ch[1]) != 2 {
			t.Errorf("Challenge %d: expected target length 2, got %d", i, len(ch[1]))
		}
	}

	// Test with store=false
	noStoreConfig := &ChallengeConfig{Store: false}
	noStoreChallenge, err := cap.CreateChallenge(noStoreConfig)
	if err != nil {
		t.Fatalf("Failed to create no-store challenge: %v", err)
	}
	if noStoreChallenge.Token != "" {
		t.Error("Expected empty token for no-store challenge")
	}
}

func TestRedeemChallenge(t *testing.T) {
	cap := New(&CapConfig{NoFSState: true})

	// Test with invalid input
	result, err := cap.RedeemChallenge(nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Success {
		t.Error("Expected failure for nil solution")
	}
	if result.Message != "Invalid body" {
		t.Errorf("Expected 'Invalid body' message, got '%s'", result.Message)
	}

	// Test with non-existent token
	invalidSolution := &Solution{
		Token:     "nonexistent",
		Solutions: [][]interface{}{{"salt", "target", 123}},
	}
	result, err = cap.RedeemChallenge(invalidSolution)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Success {
		t.Error("Expected failure for non-existent token")
	}
	if result.Message != "Challenge expired" {
		t.Errorf("Expected 'Challenge expired' message, got '%s'", result.Message)
	}

	// Create a valid challenge
	challenge, err := cap.CreateChallenge(&ChallengeConfig{
		ChallengeCount:      1,
		ChallengeDifficulty: 1, // Very easy for testing
		Store:               true,
	})
	if err != nil {
		t.Fatalf("Failed to create challenge: %v", err)
	}

	// A fixed nonce is not necessarily invalid: at difficulty 1 it matches the
	// random target with probability 1/16. Select a verified non-matching nonce
	// while keeping the salt/target correct, so this exercises PoW rejection.
	salt, target := challenge.Challenge[0][0], challenge.Challenge[0][1]
	invalidNonce := 999999
	for {
		hash := sha256.Sum256([]byte(salt + fmt.Sprint(invalidNonce)))
		if !strings.HasPrefix(hex.EncodeToString(hash[:]), target) {
			break
		}
		invalidNonce++
	}
	invalidSol := &Solution{
		Token:     challenge.Token,
		Solutions: [][]interface{}{{salt, target, invalidNonce}},
	}
	result, err = cap.RedeemChallenge(invalidSol)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Success {
		t.Error("Expected failure for invalid solution")
	}
	if result.Message != "Invalid solution" {
		t.Errorf("Expected 'Invalid solution' message, got '%s'", result.Message)
	}
}

func TestValidateToken(t *testing.T) {
	cap := New(&CapConfig{NoFSState: true})

	// Test with invalid token format
	result, err := cap.ValidateToken("invalid", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Success {
		t.Error("Expected failure for invalid token format")
	}

	// Test with non-existent token
	result, err = cap.ValidateToken("id:token", nil)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if result.Success {
		t.Error("Expected failure for non-existent token")
	}
}

func TestCleanExpiredTokens(t *testing.T) {
	cap := New(&CapConfig{NoFSState: true})

	// Add some expired tokens
	expiredTime := time.Now().UnixMilli() - 1000
	cap.config.State.TokensList["expired1"] = expiredTime
	cap.config.State.TokensList["expired2"] = expiredTime
	cap.config.State.TokensList["valid"] = time.Now().UnixMilli() + 60000

	// Add expired challenge
	cap.config.State.ChallengesList["expired_challenge"] = &ChallengeData{
		Expires: expiredTime,
		Token:   "expired_challenge",
	}

	changed := cap.cleanExpiredTokens()
	if !changed {
		t.Error("Expected tokens to be changed")
	}

	if len(cap.config.State.TokensList) != 1 {
		t.Errorf("Expected 1 token remaining, got %d", len(cap.config.State.TokensList))
	}
	if _, exists := cap.config.State.TokensList["valid"]; !exists {
		t.Error("Expected valid token to remain")
	}

	if len(cap.config.State.ChallengesList) != 0 {
		t.Errorf("Expected 0 challenges remaining, got %d", len(cap.config.State.ChallengesList))
	}
}

func TestGenerateRandomHex(t *testing.T) {
	// Test various lengths
	lengths := []int{1, 2, 8, 16, 32, 64}
	for _, length := range lengths {
		hex, err := generateRandomHex(length)
		if err != nil {
			t.Errorf("Failed to generate hex of length %d: %v", length, err)
			continue
		}
		if len(hex) != length {
			t.Errorf("Expected hex length %d, got %d", length, len(hex))
		}
		// Verify it's valid hex
		for _, char := range hex {
			if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
				t.Errorf("Invalid hex character '%c' in generated hex '%s'", char, hex)
				break
			}
		}
	}
}

func TestSHA256Verification(t *testing.T) {
	// Test the SHA-256 verification logic used in the solution validation
	salt := "abcd1234"
	target := "00"
	nonce := 0

	// Find a working nonce
	for nonce < 100000 {
		input := fmt.Sprintf("%s%d", salt, nonce)
		hash := sha256.Sum256([]byte(input))
		hashHex := hex.EncodeToString(hash[:])
		if strings.HasPrefix(hashHex, target) {
			break
		}
		nonce++
	}

	if nonce >= 100000 {
		t.Skip("Could not find a solution within reasonable attempts")
		return
	}

	// Verify the solution works
	input := fmt.Sprintf("%s%d", salt, nonce)
	hash := sha256.Sum256([]byte(input))
	hashHex := hex.EncodeToString(hash[:])
	if !strings.HasPrefix(hashHex, target) {
		t.Errorf("Solution verification failed: hash %s does not start with %s", hashHex, target)
	}
}

func TestFileOperations(t *testing.T) {
	testFile := "./test_tokens_file.json"
	defer os.Remove(testFile) // Clean up

	cap := New(&CapConfig{
		TokensStorePath: testFile,
		EnableFSState:   true,
	})

	// Add some tokens
	cap.config.State.TokensList["test1"] = time.Now().UnixMilli() + 60000
	cap.config.State.TokensList["test2"] = time.Now().UnixMilli() + 120000

	// Save tokens
	err := cap.saveTokens()
	if err != nil {
		t.Fatalf("Failed to save tokens: %v", err)
	}

	// Verify file exists
	if _, err := os.Stat(testFile); os.IsNotExist(err) {
		t.Error("Tokens file was not created")
	}

	// Create new instance and load tokens
	cap2 := New(&CapConfig{
		TokensStorePath: testFile,
		EnableFSState:   true,
	})

	if len(cap2.config.State.TokensList) != 2 {
		t.Errorf("Expected 2 loaded tokens, got %d", len(cap2.config.State.TokensList))
	}
	if _, exists := cap2.config.State.TokensList["test1"]; !exists {
		t.Error("Expected test1 token to be loaded")
	}
	if _, exists := cap2.config.State.TokensList["test2"]; !exists {
		t.Error("Expected test2 token to be loaded")
	}
}

// TestRedeemAndValidateWithPersistence walks the full flow with persistence on
// and checks the file tracks the token being issued and then consumed.
func TestRedeemAndValidateWithPersistence(t *testing.T) {
	storePath := filepath.Join(t.TempDir(), "tokensList.json")
	cap := New(&CapConfig{TokensStorePath: storePath, EnableFSState: true, SaveThrottleMs: -1})

	challenge, err := cap.CreateChallenge(&ChallengeConfig{
		ChallengeCount:      2,
		ChallengeSize:       8,
		ChallengeDifficulty: 1,
		Store:               true,
	})
	if err != nil {
		t.Fatalf("Failed to create challenge: %v", err)
	}

	solutions := make([][]interface{}, 0, len(challenge.Challenge))
	for _, ch := range challenge.Challenge {
		salt, target := ch[0], ch[1]
		found := false
		for nonce := 0; nonce < 1000000; nonce++ {
			hash := sha256.Sum256([]byte(fmt.Sprintf("%s%d", salt, nonce)))
			if strings.HasPrefix(hex.EncodeToString(hash[:]), target) {
				solutions = append(solutions, []interface{}{salt, target, nonce})
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("No solution found for salt %s target %s", salt, target)
		}
	}

	redeem, err := cap.RedeemChallenge(&Solution{Token: challenge.Token, Solutions: solutions})
	if err != nil {
		t.Fatalf("Failed to redeem challenge: %v", err)
	}
	if !redeem.Success {
		t.Fatalf("Expected redeem to succeed, got %q", redeem.Message)
	}

	readStore := func() map[string]int64 {
		data, err := os.ReadFile(storePath)
		if err != nil {
			t.Fatalf("Failed to read tokens file: %v", err)
		}
		var m map[string]int64
		if err := json.Unmarshal(data, &m); err != nil {
			t.Fatalf("Tokens file is not valid JSON: %v", err)
		}
		return m
	}

	if len(readStore()) != 1 {
		t.Errorf("Expected the issued token to be persisted, got %v", readStore())
	}

	// A fresh instance must pick the token up from disk.
	cap2 := New(&CapConfig{TokensStorePath: storePath, EnableFSState: true, SaveThrottleMs: -1})
	result, err := cap2.ValidateToken(redeem.Token, nil)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}
	if !result.Success {
		t.Fatal("Expected the reloaded token to validate")
	}

	if len(readStore()) != 0 {
		t.Errorf("Expected the consumed token to be removed from disk, got %v", readStore())
	}

	// Second use of the same token must fail.
	result, err = cap2.ValidateToken(redeem.Token, nil)
	if err != nil {
		t.Fatalf("Failed to validate token: %v", err)
	}
	if result.Success {
		t.Error("Expected a consumed token to be rejected")
	}
}

func TestCleanup(t *testing.T) {
	testFile := "./test_cleanup_tokens.json"
	defer os.Remove(testFile) // Clean up

	cap := New(&CapConfig{
		TokensStorePath: testFile,
		EnableFSState:   true,
	})

	// Add expired and valid tokens
	expiredTime := time.Now().UnixMilli() - 1000
	validTime := time.Now().UnixMilli() + 60000
	cap.config.State.TokensList["expired"] = expiredTime
	cap.config.State.TokensList["valid"] = validTime

	err := cap.Cleanup()
	if err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	if len(cap.config.State.TokensList) != 1 {
		t.Errorf("Expected 1 token after cleanup, got %d", len(cap.config.State.TokensList))
	}
	if _, exists := cap.config.State.TokensList["valid"]; !exists {
		t.Error("Expected valid token to remain after cleanup")
	}
}

func BenchmarkCreateChallenge(b *testing.B) {
	cap := New(&CapConfig{NoFSState: true})
	config := &ChallengeConfig{
		ChallengeCount: 50,
		Store:          false, // Don't store for benchmark
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := cap.CreateChallenge(config)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateRandomHex(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := generateRandomHex(32)
		if err != nil {
			b.Fatal(err)
		}
	}
}

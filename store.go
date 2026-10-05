package capserver

import (
	"context"
	"errors"
	"sync"
	"time"
)

// Store persists opaque engine records. Implementations MUST make PutIfAbsent
// and Take atomic across all their users, enforce expiresAt on reads, and return
// owned byte slices. A missing/expired key is (nil,false,nil). Never evict live
// records to make space: dropping a replay marker permits a repeated redemption.
// Engine keys are namespaced by secret, scope, and record kind.
type Store interface {
	Put(context.Context, string, []byte, time.Time) error
	PutIfAbsent(context.Context, string, []byte, time.Time) (bool, error)
	Get(context.Context, string) ([]byte, bool, error)
	Take(context.Context, string) ([]byte, bool, error)
}

var ErrStoreFull = errors.New("cap: store capacity exhausted")

type memoryEntry struct {
	value   []byte
	expires time.Time
}

// MemoryStore is bounded and race safe. It needs no background goroutine.
// Every write cleans expired entries; reads remove an expired requested key.
type MemoryStore struct {
	mu       sync.Mutex
	entries  map[string]memoryEntry
	capacity int
}

func NewMemoryStore(capacity int) *MemoryStore {
	if capacity <= 0 {
		capacity = 10000
	}
	return &MemoryStore{entries: make(map[string]memoryEntry), capacity: capacity}
}
func (s *MemoryStore) cleanup(now time.Time) int {
	n := 0
	for k, v := range s.entries {
		if !now.Before(v.expires) {
			delete(s.entries, k)
			n++
		}
	}
	return n
}
func (s *MemoryStore) Cleanup() int { s.mu.Lock(); defer s.mu.Unlock(); return s.cleanup(time.Now()) }
func (s *MemoryStore) put(ctx context.Context, k string, v []byte, exp time.Time, absent bool) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	now := time.Now()
	s.cleanup(now)
	if !exp.After(now) {
		return false, errors.New("cap: store expiration must be in the future")
	}
	_, exists := s.entries[k]
	if absent && exists {
		return false, nil
	}
	if !exists && len(s.entries) >= s.capacity {
		return false, ErrStoreFull
	}
	s.entries[k] = memoryEntry{append([]byte(nil), v...), exp}
	return true, nil
}
func (s *MemoryStore) Put(ctx context.Context, k string, v []byte, exp time.Time) error {
	_, err := s.put(ctx, k, v, exp, false)
	return err
}
func (s *MemoryStore) PutIfAbsent(ctx context.Context, k string, v []byte, exp time.Time) (bool, error) {
	return s.put(ctx, k, v, exp, true)
}
func (s *MemoryStore) read(ctx context.Context, k string, take bool) ([]byte, bool, error) {
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, false, err
	}
	v, ok := s.entries[k]
	if !ok {
		return nil, false, nil
	}
	if !time.Now().Before(v.expires) {
		delete(s.entries, k)
		return nil, false, nil
	}
	if take {
		delete(s.entries, k)
	}
	return append([]byte(nil), v.value...), true, nil
}
func (s *MemoryStore) Get(ctx context.Context, k string) ([]byte, bool, error) {
	return s.read(ctx, k, false)
}
func (s *MemoryStore) Take(ctx context.Context, k string) ([]byte, bool, error) {
	return s.read(ctx, k, true)
}

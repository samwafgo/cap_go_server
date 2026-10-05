package capserver

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestMemoryStoreCapacityExpiryAndCopies(t *testing.T) {
	s := NewMemoryStore(1)
	ctx := context.Background()
	exp := time.Now().Add(time.Minute)
	v := []byte("value")
	if err := s.Put(ctx, "a", v, exp); err != nil {
		t.Fatal(err)
	}
	v[0] = 'X'
	got, ok, err := s.Get(ctx, "a")
	if err != nil || !ok || string(got) != "value" {
		t.Fatal(string(got), ok, err)
	}
	got[0] = 'Y'
	got, _, _ = s.Get(ctx, "a")
	if string(got) != "value" {
		t.Fatal("read alias")
	}
	if err = s.Put(ctx, "b", nil, exp); !errors.Is(err, ErrStoreFull) {
		t.Fatal(err)
	}
	ok, err = s.PutIfAbsent(ctx, "a", nil, exp)
	if err != nil || ok {
		t.Fatal(ok, err)
	}
	s.mu.Lock()
	s.entries["a"] = memoryEntry{expires: time.Now().Add(-time.Second)}
	s.mu.Unlock()
	if err = s.Put(ctx, "b", nil, exp); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ = s.Get(ctx, "a"); ok {
		t.Fatal("expired survived")
	}
	if err = s.Put(ctx, "b", nil, time.Now().Add(-time.Second)); err == nil {
		t.Fatal("past expiry")
	}
}
func TestMemoryStoreAtomic(t *testing.T) {
	s := NewMemoryStore(10)
	ctx := context.Background()
	var won atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ok, err := s.PutIfAbsent(ctx, "x", []byte("v"), time.Now().Add(time.Minute))
			if err != nil {
				t.Error(err)
			}
			if ok {
				won.Add(1)
			}
		}()
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Fatal(won.Load())
	}
	won.Store(0)
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, ok, err := s.Take(ctx, "x")
			if err != nil {
				t.Error(err)
			}
			if ok {
				won.Add(1)
			}
		}()
	}
	wg.Wait()
	if won.Load() != 1 {
		t.Fatal(won.Load())
	}
	ctx, cancel := context.WithCancel(ctx)
	cancel()
	if err := s.Put(ctx, "y", nil, time.Now().Add(time.Minute)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

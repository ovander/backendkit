package bff

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// pendingLoginSuite is the behaviour every PendingLoginStore must have.
func pendingLoginSuite(t *testing.T, newStore func(t *testing.T, ttl time.Duration) PendingLoginStore) {
	ctx := context.Background()

	t.Run("round trip, then single use", func(t *testing.T) {
		s := newStore(t, time.Minute)
		in := PendingLogin{Verifier: "v-secret", Nonce: "n1", ReturnTo: "/alerts"}
		if err := s.Put(ctx, "st-1", in); err != nil {
			t.Fatal(err)
		}
		got, ok := s.Take(ctx, "st-1")
		if !ok || got.Verifier != in.Verifier || got.Nonce != in.Nonce || got.ReturnTo != in.ReturnTo || got.Created.IsZero() {
			t.Fatalf("Take = %+v, %v", got, ok)
		}
		if _, ok := s.Take(ctx, "st-1"); ok {
			t.Error("a state must be accepted only once")
		}
	})

	t.Run("unknown state", func(t *testing.T) {
		s := newStore(t, time.Minute)
		if _, ok := s.Take(ctx, "never-issued"); ok {
			t.Error("an unknown state was accepted")
		}
	})

	t.Run("expired state is refused and swept", func(t *testing.T) {
		s := newStore(t, time.Minute)
		old := PendingLogin{Verifier: "v", Nonce: "n", Created: time.Now().Add(-2 * time.Minute)}
		if err := s.Put(ctx, "st-old", old); err != nil {
			t.Fatal(err)
		}
		if _, ok := s.Take(ctx, "st-old"); ok {
			t.Error("an expired state was accepted")
		}
		if err := s.Put(ctx, "st-old2", old); err != nil {
			t.Fatal(err)
		}
		s.Sweep(ctx)
		if err := s.Put(ctx, "st-new", PendingLogin{Verifier: "v"}); err != nil {
			t.Fatal(err)
		}
		s.Sweep(ctx)
		if _, ok := s.Take(ctx, "st-new"); !ok {
			t.Error("Sweep removed a live state")
		}
	})

	t.Run("concurrent takes: exactly one wins", func(t *testing.T) {
		s := newStore(t, time.Minute)
		if err := s.Put(ctx, "st-race", PendingLogin{Verifier: "v", Nonce: "n"}); err != nil {
			t.Fatal(err)
		}
		var wins atomic.Int32
		var wg sync.WaitGroup
		for range 16 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, ok := s.Take(ctx, "st-race"); ok {
					wins.Add(1)
				}
			}()
		}
		wg.Wait()
		if wins.Load() != 1 {
			t.Errorf("%d takes succeeded, want exactly 1", wins.Load())
		}
	})

	t.Run("empty state is refused", func(t *testing.T) {
		if err := newStore(t, time.Minute).Put(ctx, "", PendingLogin{Verifier: "v"}); err == nil {
			t.Error("Put accepted an empty state")
		}
	})
}

func TestMemoryPendingLoginStore(t *testing.T) {
	pendingLoginSuite(t, func(_ *testing.T, ttl time.Duration) PendingLoginStore {
		return NewMemoryPendingLoginStore(ttl, 0)
	})
}

// The memory store is bounded: /login needs no session.
func TestMemoryPendingLoginStore_Bounded(t *testing.T) {
	ctx := context.Background()
	s := NewMemoryPendingLoginStore(time.Minute, 2)
	_ = s.Put(ctx, "a", PendingLogin{})
	_ = s.Put(ctx, "b", PendingLogin{})
	if err := s.Put(ctx, "c", PendingLogin{}); err != ErrPendingLoginsFull {
		t.Fatalf("third Put = %v, want ErrPendingLoginsFull", err)
	}
	if err := s.Put(ctx, "a", PendingLogin{Verifier: "again"}); err != nil {
		t.Errorf("replacing an existing state must not count against the bound: %v", err)
	}
	s.Take(ctx, "b")
	if err := s.Put(ctx, "c", PendingLogin{}); err != nil {
		t.Errorf("a freed place must be reusable: %v", err)
	}
	// Expired entries are dropped to make room.
	full := NewMemoryPendingLoginStore(time.Minute, 1)
	_ = full.Put(ctx, "old", PendingLogin{Created: time.Now().Add(-time.Hour)})
	if err := full.Put(ctx, "new", PendingLogin{}); err != nil {
		t.Errorf("an expired entry must not block a new one: %v", err)
	}
}

func pgPendingStore(t *testing.T, ttl time.Duration, opts ...PendingLoginStoreOption) (*PostgresPendingLoginStore, *sql.DB) {
	t.Helper()
	_, db := pgStore(t, time.Hour, time.Hour) // same database setup as the session store tests
	table := fmt.Sprintf("bff_test_pending_%d", time.Now().UnixNano())
	opts = append([]PendingLoginStoreOption{WithPendingLoginTable(table), WithPendingLoginAutoSchema(),
		WithPendingLoginErrorHandler(func(op string, err error) { t.Errorf("%s: %v", op, err) })}, opts...)
	s, err := NewPostgresPendingLoginStore(context.Background(), db, testKey, ttl, opts...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec("DROP TABLE IF EXISTS " + table) })
	return s, db
}

func TestPostgresPendingLoginStore(t *testing.T) {
	pendingLoginSuite(t, func(t *testing.T, ttl time.Duration) PendingLoginStore {
		s, _ := pgPendingStore(t, ttl)
		return s
	})
}

// A login started on one instance completes on another; the verifier is not
// stored in clear, and a row moved to another state does not decrypt.
func TestPostgresPendingLoginStore_SharedAndSealed(t *testing.T) {
	ctx := context.Background()
	a, db := pgPendingStore(t, time.Minute)
	b, err := NewPostgresPendingLoginStore(ctx, db, testKey, time.Minute, WithPendingLoginTable(a.table))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Put(ctx, "st-x", PendingLogin{Verifier: "pkce-verifier-secret", Nonce: "n"}); err != nil {
		t.Fatal(err)
	}
	var raw []byte
	if err := db.QueryRow("SELECT data FROM " + a.table + " WHERE state = 'st-x'").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || strings.Contains(string(raw), "pkce-verifier-secret") {
		t.Fatal("the verifier is stored in clear")
	}
	if got, ok := b.Take(ctx, "st-x"); !ok || got.Verifier != "pkce-verifier-secret" {
		t.Fatalf("another instance: %+v, %v", got, ok)
	}

	// A sealed row copied under another state is refused (bound to its state).
	_ = a.Put(ctx, "st-y", PendingLogin{Verifier: "v"})
	if _, err := db.Exec("UPDATE " + a.table + " SET state = 'st-z' WHERE state = 'st-y'"); err != nil {
		t.Fatal(err)
	}
	quiet, _ := NewPostgresPendingLoginStore(ctx, db, testKey, time.Minute, WithPendingLoginTable(a.table),
		WithPendingLoginErrorHandler(func(string, error) {}))
	if _, ok := quiet.Take(ctx, "st-z"); ok {
		t.Error("a row moved to another state decrypted")
	}
}

func TestPostgresPendingLoginStore_ManagedSchema(t *testing.T) {
	ctx := context.Background()
	_, db := pgStore(t, time.Hour, time.Hour)
	table := fmt.Sprintf("bff_test_pending_managed_%d", time.Now().UnixNano())
	t.Cleanup(func() { _, _ = db.Exec("DROP TABLE IF EXISTS " + table) })
	if _, err := NewPostgresPendingLoginStore(ctx, db, testKey, 0, WithPendingLoginTable(table), WithPendingLoginManagedSchema()); err == nil {
		t.Fatal("managed schema with no table must fail at start-up")
	}
	if _, err := db.Exec("CREATE TABLE " + table + " (state text PRIMARY KEY, data bytea NOT NULL, created_at timestamptz NOT NULL)"); err != nil {
		t.Fatal(err)
	}
	s, err := NewPostgresPendingLoginStore(ctx, db, testKey, 0, WithPendingLoginTable(table), WithPendingLoginManagedSchema())
	if err != nil {
		t.Fatalf("managed schema over the migrated table: %v", err)
	}
	if err := s.Put(ctx, "st", PendingLogin{Verifier: "v"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.Take(ctx, "st"); !ok {
		t.Error("round trip on the managed table failed")
	}
}

func TestNewPostgresPendingLoginStore_Validation(t *testing.T) {
	ctx := context.Background()
	if _, err := NewPostgresPendingLoginStore(ctx, nil, testKey, 0); err == nil {
		t.Error("nil db accepted")
	}
	if os.Getenv("TEST_DATABASE_URL") == "" && os.Getenv("CI") == "" {
		return
	}
	_, db := pgStore(t, time.Hour, time.Hour)
	if _, err := NewPostgresPendingLoginStore(ctx, db, []byte("short"), 0); err == nil {
		t.Error("a short key was accepted")
	}
	if _, err := NewPostgresPendingLoginStore(ctx, db, testKey, 0, WithPendingLoginTable("bad name;")); err == nil {
		t.Error("an invalid table name was accepted")
	}
}

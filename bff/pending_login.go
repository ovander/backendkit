package bff

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"
)

// DefaultPendingLoginTTL bounds how long a login may take between the redirect
// to Socrate and the callback. It matches DefaultLoginBindingTTL.
const DefaultPendingLoginTTL = DefaultLoginBindingTTL

// DefaultMaxPendingLogins bounds a MemoryPendingLoginStore. /login is reachable
// without a session, so the number of pending logins must be bounded.
const DefaultMaxPendingLogins = 10000

// ErrPendingLoginsFull is returned by MemoryPendingLoginStore.Put when the
// store holds its maximum of unexpired pending logins.
var ErrPendingLoginsFull = errors.New("bff: too many pending logins")

// PendingLogin is the server-side half of a login in flight, from the
// redirect to Socrate's authorize endpoint to the callback, keyed by the OAuth
// state. The Verifier is the PKCE secret and must never reach the browser.
type PendingLogin struct {
	Verifier string    `json:"verifier"`
	Nonce    string    `json:"nonce"`     // the LoginBinding nonce
	ReturnTo string    `json:"return_to"` // already validated (see SafeRedirect)
	Created  time.Time `json:"created"`
}

// PendingLoginStore keeps pending logins between /login and the callback. Put
// stores one under its state; Take returns it and removes it in one step, so a
// state is accepted at most once, and reports false for an unknown or expired
// state (and on any storage error: a callback is refused rather than guessed).
// Behind several BFF instances, use a shared store (PostgresPendingLoginStore)
// so a login started on one instance completes on another. An application may
// provide its own implementation, for example one that seals the verifier
// into an encrypted value instead of storing it.
type PendingLoginStore interface {
	Put(ctx context.Context, state string, p PendingLogin) error
	Take(ctx context.Context, state string) (PendingLogin, bool)
	// Sweep removes expired pending logins; a background ticker should call it.
	Sweep(ctx context.Context)
}

// MemoryPendingLoginStore is a PendingLoginStore for a single BFF instance.
type MemoryPendingLoginStore struct {
	mu  sync.Mutex
	m   map[string]PendingLogin
	ttl time.Duration
	max int
	now func() time.Time
}

// NewMemoryPendingLoginStore returns a MemoryPendingLoginStore keeping each
// pending login for ttl (zero: DefaultPendingLoginTTL) and at most max of
// them (zero: DefaultMaxPendingLogins). When full, Put first drops expired
// entries, then refuses with ErrPendingLoginsFull: new sign-ins fail until
// older ones finish or expire, rather than memory growing without bound.
func NewMemoryPendingLoginStore(ttl time.Duration, max int) *MemoryPendingLoginStore {
	if ttl <= 0 {
		ttl = DefaultPendingLoginTTL
	}
	if max <= 0 {
		max = DefaultMaxPendingLogins
	}
	return &MemoryPendingLoginStore{m: map[string]PendingLogin{}, ttl: ttl, max: max, now: time.Now}
}

// Put stores p under state. A zero p.Created is set to now.
func (s *MemoryPendingLoginStore) Put(_ context.Context, state string, p PendingLogin) error {
	if state == "" {
		return errors.New("bff: pending login: empty state")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if p.Created.IsZero() {
		p.Created = s.now()
	}
	if _, exists := s.m[state]; !exists && len(s.m) >= s.max {
		s.sweepLocked()
		if len(s.m) >= s.max {
			return ErrPendingLoginsFull
		}
	}
	s.m[state] = p
	return nil
}

// Take returns and removes the pending login for state.
func (s *MemoryPendingLoginStore) Take(_ context.Context, state string) (PendingLogin, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.m[state]
	if !ok {
		return PendingLogin{}, false
	}
	delete(s.m, state)
	if s.now().Sub(p.Created) > s.ttl {
		return PendingLogin{}, false
	}
	return p, true
}

// Sweep removes expired pending logins.
func (s *MemoryPendingLoginStore) Sweep(context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweepLocked()
}

func (s *MemoryPendingLoginStore) sweepLocked() {
	now := s.now()
	for k, p := range s.m {
		if now.Sub(p.Created) > s.ttl {
			delete(s.m, k)
		}
	}
}

var _ PendingLoginStore = (*MemoryPendingLoginStore)(nil)

// PostgresPendingLoginStore is a PendingLoginStore in PostgreSQL, shared by
// every BFF instance. Each pending login is one row whose data (verifier,
// nonce, return path) is encrypted with AES-256-GCM under the store's key,
// bound to its state, so a copy of the database reveals no PKCE verifier.
// Take is a single DELETE … RETURNING, so a state is accepted at most once
// even when two instances race on the same callback.
type PostgresPendingLoginStore struct {
	db      *sql.DB
	aead    cipher.AEAD
	table   string
	ttl     time.Duration
	now     func() time.Time
	onError func(op string, err error)
	managed bool
	auto    bool
}

// PendingLoginStoreOption configures a PostgresPendingLoginStore.
type PendingLoginStoreOption func(*PostgresPendingLoginStore)

// WithPendingLoginTable sets the table name (default
// "bff_store_pending_logins"): a lower-case SQL identifier, checked by
// NewPostgresPendingLoginStore.
func WithPendingLoginTable(name string) PendingLoginStoreOption {
	return func(s *PostgresPendingLoginStore) { s.table = name }
}

// WithPendingLoginErrorHandler sets the function told about failed
// statements. The default logs them with the standard logger.
func WithPendingLoginErrorHandler(f func(op string, err error)) PendingLoginStoreOption {
	return func(s *PostgresPendingLoginStore) { s.onError = f }
}

// WithPendingLoginManagedSchema tells NewPostgresPendingLoginStore that the
// table is created by the caller's own migrations, as for
// WithPostgresManagedSchema: it runs no DDL, checks the columns and that the
// role holds SELECT, INSERT, UPDATE and DELETE (Put is an INSERT … ON CONFLICT
// DO UPDATE, which needs UPDATE). The migration must create:
//
//	CREATE TABLE <table> (
//		state      text        PRIMARY KEY,
//		data       bytea       NOT NULL,
//		created_at timestamptz NOT NULL
//	);
func WithPendingLoginManagedSchema() PendingLoginStoreOption {
	return func(s *PostgresPendingLoginStore) { s.managed = true }
}

// WithPendingLoginAutoSchema tells NewPostgresPendingLoginStore to create its
// table itself, as WithPostgresAutoSchema does for the session store; without
// either schema option it does the same and logs a start-up warning. It
// cannot be combined with WithPendingLoginManagedSchema.
func WithPendingLoginAutoSchema() PendingLoginStoreOption {
	return func(s *PostgresPendingLoginStore) { s.auto = true }
}

// NewPostgresPendingLoginStore checks the connection, creates the table if it
// does not exist (or, with WithPendingLoginManagedSchema, checks the existing
// one) and returns the store. key must be 32 bytes (AES-256); the session
// store's key may be reused. ttl is as for NewMemoryPendingLoginStore.
func NewPostgresPendingLoginStore(ctx context.Context, db *sql.DB, key []byte, ttl time.Duration, opts ...PendingLoginStoreOption) (*PostgresPendingLoginStore, error) {
	if db == nil {
		return nil, errors.New("bff: pending login store: nil *sql.DB")
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("bff: pending login store: key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("bff: pending login store: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("bff: pending login store: %w", err)
	}
	if ttl <= 0 {
		ttl = DefaultPendingLoginTTL
	}
	s := &PostgresPendingLoginStore{
		db: db, aead: aead, table: "bff_store_pending_logins", ttl: ttl, now: time.Now,
		onError: func(op string, err error) { log.Printf("bff: pending login store: %s: %v", op, err) },
	}
	for _, opt := range opts {
		opt(s)
	}
	if !tableNamePattern.MatchString(s.table) {
		return nil, fmt.Errorf("bff: pending login store: invalid table name %q", s.table)
	}
	if s.managed && s.auto {
		return nil, errors.New("bff: pending login store: WithPendingLoginManagedSchema and WithPendingLoginAutoSchema contradict each other")
	}
	if !s.managed && !s.auto {
		log.Printf("bff: pending login store: neither WithPendingLoginManagedSchema nor WithPendingLoginAutoSchema given; "+
			"creating table %s at start-up. Pass WithPendingLoginAutoSchema to keep this, or create the table in your "+
			"migrations and pass WithPendingLoginManagedSchema (see its doc comment)", s.table)
	}
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("bff: pending login store: %w", err)
	}
	if s.managed {
		if err := checkTable(ctx, db, s.table, "state, data, created_at", "SELECT", "INSERT", "UPDATE", "DELETE"); err != nil {
			return nil, fmt.Errorf("bff: pending login store: managed table %s: %w", s.table, err)
		}
		return s, nil
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS `+s.table+` (
		state      text        PRIMARY KEY,
		data       bytea       NOT NULL,
		created_at timestamptz NOT NULL
	)`); err != nil {
		return nil, fmt.Errorf("bff: pending login store: create table: %w", err)
	}
	return s, nil
}

// Put stores p under state. A zero p.Created is set to now.
func (s *PostgresPendingLoginStore) Put(ctx context.Context, state string, p PendingLogin) error {
	if state == "" {
		return errors.New("bff: pending login: empty state")
	}
	if p.Created.IsZero() {
		p.Created = s.now()
	}
	plain, err := json.Marshal(p)
	if err != nil {
		return err
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	data := s.aead.Seal(nonce, nonce, plain, []byte(state))
	ctx, cancel := context.WithTimeout(ctx, postgresStoreOpTimeout)
	defer cancel()
	_, err = s.db.ExecContext(ctx, `INSERT INTO `+s.table+` (state, data, created_at) VALUES ($1, $2, $3)
		ON CONFLICT (state) DO UPDATE SET data = EXCLUDED.data, created_at = EXCLUDED.created_at`,
		state, data, p.Created)
	if err != nil {
		s.onError("put", err)
		return fmt.Errorf("bff: pending login store: put: %w", err)
	}
	return nil
}

// Take returns and removes the pending login for state, in one statement.
func (s *PostgresPendingLoginStore) Take(ctx context.Context, state string) (PendingLogin, bool) {
	ctx, cancel := context.WithTimeout(ctx, postgresStoreOpTimeout)
	defer cancel()
	var data []byte
	err := s.db.QueryRowContext(ctx, `DELETE FROM `+s.table+` WHERE state = $1 RETURNING data`, state).Scan(&data)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			s.onError("take", err)
		}
		return PendingLogin{}, false
	}
	n := s.aead.NonceSize()
	if len(data) < n {
		s.onError("take", errors.New("ciphertext too short"))
		return PendingLogin{}, false
	}
	plain, err := s.aead.Open(nil, data[:n], data[n:], []byte(state))
	if err != nil {
		s.onError("take", err)
		return PendingLogin{}, false
	}
	var p PendingLogin
	if err := json.Unmarshal(plain, &p); err != nil {
		s.onError("take", err)
		return PendingLogin{}, false
	}
	if s.now().Sub(p.Created) > s.ttl {
		return PendingLogin{}, false
	}
	return p, true
}

// Sweep removes expired pending logins.
func (s *PostgresPendingLoginStore) Sweep(ctx context.Context) {
	ctx, cancel := context.WithTimeout(ctx, postgresStoreOpTimeout)
	defer cancel()
	if _, err := s.db.ExecContext(ctx, `DELETE FROM `+s.table+` WHERE created_at < $1`, s.now().Add(-s.ttl)); err != nil {
		s.onError("sweep", err)
	}
}

var _ PendingLoginStore = (*PostgresPendingLoginStore)(nil)

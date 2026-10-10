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
	"regexp"
	"time"
)

// PostgresStore is a durable SessionStore in PostgreSQL: sessions survive a
// restart of the BFF and are shared by several instances, unlike MemoryStore.
//
// It works through database/sql, so the application chooses the driver and
// owns the *sql.DB (for example pgx's stdlib: sql.Open("pgx", dsn)); the
// package imports none. Each session is stored as one row whose token-bearing
// data is encrypted with AES-256-GCM under the key given to NewPostgresStore,
// so a copy of the database does not hand out live refresh tokens. Expiry is
// the same sliding idle window and absolute lifetime as MemoryStore, enforced
// on Get and by Sweep.
//
// Delete wipes the session's data and keeps a tombstone for an hour, so a
// request that was in flight during a logout cannot bring the session back
// with a later Put. The SessionStore interface returns no errors: a failed
// statement reads as "no session" (fail closed) and is reported to the error
// handler (by default the standard logger).
type PostgresStore struct {
	db       *sql.DB
	aead     cipher.AEAD
	table    string
	idle     time.Duration
	absolute time.Duration
	now      func() time.Time
	onError  func(op string, err error)
	managed  bool
	auto     bool
}

// PostgresStoreTombstoneTTL is how long Delete keeps a tombstone that stops a
// racing Put from re-creating a deleted session.
const PostgresStoreTombstoneTTL = time.Hour

// postgresStoreOpTimeout bounds each statement: the SessionStore interface
// carries no context.
const postgresStoreOpTimeout = 5 * time.Second

var tableNamePattern = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// PostgresStoreOption configures a PostgresStore.
type PostgresStoreOption func(*PostgresStore)

// WithPostgresTable sets the table name (default "bff_store_sessions"): a
// lower-case SQL identifier, checked by NewPostgresStore.
func WithPostgresTable(name string) PostgresStoreOption {
	return func(p *PostgresStore) { p.table = name }
}

// WithPostgresErrorHandler sets the function told about failed statements.
// The default logs them with the standard logger; op names the operation.
func WithPostgresErrorHandler(f func(op string, err error)) PostgresStoreOption {
	return func(p *PostgresStore) { p.onError = f }
}

// WithPostgresManagedSchema tells NewPostgresStore that the table and its
// last_seen index are created by the caller's own migrations, so it runs no
// DDL and the store can use a role holding only SELECT, INSERT, UPDATE and
// DELETE on the table: PostgreSQL checks CREATE on the schema, and table
// ownership for the index, even when the objects already exist.
// NewPostgresStore then checks that the table has the expected columns and
// that the role holds each of those four privileges, and fails otherwise. The
// migration must create, under the configured name (WithPostgresTable;
// unqualified, so resolved through the role's search_path):
//
//	CREATE TABLE <table> (
//		id         text        PRIMARY KEY,
//		data       bytea       NOT NULL,
//		created_at timestamptz NOT NULL,
//		last_seen  timestamptz NOT NULL,
//		deleted_at timestamptz
//	);
//	CREATE INDEX <table>_last_seen_idx ON <table> (last_seen);
func WithPostgresManagedSchema() PostgresStoreOption {
	return func(p *PostgresStore) { p.managed = true }
}

// WithPostgresAutoSchema tells NewPostgresStore to create its table and index
// itself (CREATE … IF NOT EXISTS), which needs CREATE on the schema and
// ownership of the table. This is what NewPostgresStore does with neither
// schema option, but without either it also logs a start-up warning: name the
// choice explicitly. Prefer WithPostgresManagedSchema in production; a future
// major version may make it the default. It cannot be combined with
// WithPostgresManagedSchema.
func WithPostgresAutoSchema() PostgresStoreOption {
	return func(p *PostgresStore) { p.auto = true }
}

// NewPostgresStore checks the connection, creates the table if it does not
// exist (or, with WithPostgresManagedSchema, checks the existing one) and
// returns the store. key encrypts the session data and must be 32
// bytes (AES-256); keep it with the BFF's other secrets. Changing it signs
// every user out. idle and absolute are as for NewMemoryStore; zero disables
// that bound.
func NewPostgresStore(ctx context.Context, db *sql.DB, key []byte, idle, absolute time.Duration, opts ...PostgresStoreOption) (*PostgresStore, error) {
	if db == nil {
		return nil, errors.New("bff: postgres store: nil *sql.DB")
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("bff: postgres store: key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("bff: postgres store: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("bff: postgres store: %w", err)
	}
	p := &PostgresStore{
		db: db, aead: aead, table: "bff_store_sessions", idle: idle, absolute: absolute,
		now: time.Now,
		onError: func(op string, err error) {
			log.Printf("bff: postgres store: %s: %v", op, err)
		},
	}
	for _, opt := range opts {
		opt(p)
	}
	if !tableNamePattern.MatchString(p.table) {
		return nil, fmt.Errorf("bff: postgres store: invalid table name %q", p.table)
	}
	if p.managed && p.auto {
		return nil, errors.New("bff: postgres store: WithPostgresManagedSchema and WithPostgresAutoSchema contradict each other")
	}
	if !p.managed && !p.auto {
		log.Printf("bff: postgres store: neither WithPostgresManagedSchema nor WithPostgresAutoSchema given; "+
			"creating table %s at start-up. Pass WithPostgresAutoSchema to keep this, or create the table in your "+
			"migrations and pass WithPostgresManagedSchema (see its doc comment)", p.table)
	}
	if err := db.PingContext(ctx); err != nil {
		return nil, fmt.Errorf("bff: postgres store: %w", err)
	}
	if p.managed {
		if err := p.checkManagedTable(ctx); err != nil {
			return nil, fmt.Errorf("bff: postgres store: managed table %s: %w", p.table, err)
		}
		return p, nil
	}
	if _, err := db.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS `+p.table+` (
		id         text        PRIMARY KEY,
		data       bytea       NOT NULL,
		created_at timestamptz NOT NULL,
		last_seen  timestamptz NOT NULL,
		deleted_at timestamptz
	)`); err != nil {
		return nil, fmt.Errorf("bff: postgres store: create table: %w", err)
	}
	if _, err := db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS `+p.table+`_last_seen_idx ON `+p.table+` (last_seen)`); err != nil {
		return nil, fmt.Errorf("bff: postgres store: create index: %w", err)
	}
	return p, nil
}

// checkManagedTable verifies, without DDL, that the migration-owned table has
// the columns the store uses and that the role may read and write it, so a
// missing grant fails at start-up rather than at the first sign-in.
func (p *PostgresStore) checkManagedTable(ctx context.Context) error {
	return checkTable(ctx, p.db, p.table, "id, data, created_at, last_seen, deleted_at", "SELECT", "INSERT", "UPDATE", "DELETE")
}

// checkTable verifies, without DDL, that table has columns (a comma-separated
// list) and that the role holds each of privileges on it. table is a checked
// identifier.
func checkTable(ctx context.Context, db *sql.DB, table, columns string, privileges ...string) error {
	// LIMIT 0 reads no row.
	rows, err := db.QueryContext(ctx, `SELECT `+columns+` FROM `+table+` LIMIT 0`)
	if err != nil {
		return err
	}
	if err := rows.Close(); err != nil {
		return err
	}
	// One call per privilege: given a list, has_table_privilege is true when
	// any of them is held.
	for _, priv := range privileges {
		var ok bool
		if err := db.QueryRowContext(ctx, `SELECT has_table_privilege($1, $2)`, table, priv).Scan(&ok); err != nil {
			return err
		}
		if !ok {
			return fmt.Errorf("the role lacks %s on the table", priv)
		}
	}
	return nil
}

func opContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), postgresStoreOpTimeout)
}

// seal encrypts plaintext with the session ID as additional data, so a row's
// data cannot be moved to another session ID.
func (p *PostgresStore) seal(id string, plaintext []byte) ([]byte, error) {
	nonce := make([]byte, p.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	return p.aead.Seal(nonce, nonce, plaintext, []byte(id)), nil
}

func (p *PostgresStore) open(id string, data []byte) ([]byte, error) {
	n := p.aead.NonceSize()
	if len(data) < n {
		return nil, errors.New("ciphertext too short")
	}
	return p.aead.Open(nil, data[:n], data[n:], []byte(id))
}

func (p *PostgresStore) expired(created, lastSeen time.Time) bool {
	now := p.now()
	if p.absolute > 0 && now.Sub(created) >= p.absolute {
		return true
	}
	return p.idle > 0 && now.Sub(lastSeen) >= p.idle
}

// Get returns the live session for id, or (nil, false) when it is missing,
// deleted, expired (the row is then removed) or unreadable.
func (p *PostgresStore) Get(id string) (*Session, bool) {
	ctx, cancel := opContext()
	defer cancel()
	var data []byte
	err := p.db.QueryRowContext(ctx,
		`SELECT data FROM `+p.table+` WHERE id = $1 AND deleted_at IS NULL`, id).Scan(&data)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			p.onError("get", err)
		}
		return nil, false
	}
	plain, err := p.open(id, data)
	if err != nil {
		p.onError("get: decrypt", err)
		return nil, false
	}
	var snap SessionSnapshot
	if err := json.Unmarshal(plain, &snap); err != nil || snap.ID != id {
		p.onError("get: decode", fmt.Errorf("invalid session data: %v", err))
		return nil, false
	}
	if p.expired(snap.Created, snap.LastSeen) {
		p.remove(id)
		return nil, false
	}
	return NewSessionFromSnapshot(snap), true
}

// Put stores or replaces a session. It never re-creates a deleted one.
func (p *PostgresStore) Put(s *Session) {
	snap := s.Snapshot()
	plain, err := json.Marshal(snap)
	if err != nil {
		p.onError("put: encode", err)
		return
	}
	data, err := p.seal(snap.ID, plain)
	if err != nil {
		p.onError("put: encrypt", err)
		return
	}
	ctx, cancel := opContext()
	defer cancel()
	if _, err := p.db.ExecContext(ctx, `INSERT INTO `+p.table+` (id, data, created_at, last_seen)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, last_seen = EXCLUDED.last_seen
		WHERE `+p.table+`.deleted_at IS NULL`,
		snap.ID, data, snap.Created, snap.LastSeen); err != nil {
		p.onError("put", err)
	}
}

// Delete ends a session: its data is wiped and a tombstone kept for
// PostgresStoreTombstoneTTL.
func (p *PostgresStore) Delete(id string) {
	ctx, cancel := opContext()
	defer cancel()
	if _, err := p.db.ExecContext(ctx,
		`UPDATE `+p.table+` SET data = '\x', deleted_at = $2 WHERE id = $1`, id, p.now()); err != nil {
		p.onError("delete", err)
	}
}

// remove drops an expired session's row.
func (p *PostgresStore) remove(id string) {
	ctx, cancel := opContext()
	defer cancel()
	if _, err := p.db.ExecContext(ctx, `DELETE FROM `+p.table+` WHERE id = $1`, id); err != nil {
		p.onError("remove", err)
	}
}

// Sweep removes expired sessions and tombstones older than
// PostgresStoreTombstoneTTL. Call it from a background ticker.
func (p *PostgresStore) Sweep() {
	now := p.now()
	where := `(deleted_at IS NOT NULL AND deleted_at < $1)`
	args := []any{now.Add(-PostgresStoreTombstoneTTL)}
	if p.absolute > 0 {
		args = append(args, now.Add(-p.absolute))
		where += fmt.Sprintf(` OR (deleted_at IS NULL AND created_at <= $%d)`, len(args))
	}
	if p.idle > 0 {
		args = append(args, now.Add(-p.idle))
		where += fmt.Sprintf(` OR (deleted_at IS NULL AND last_seen <= $%d)`, len(args))
	}
	ctx, cancel := opContext()
	defer cancel()
	if _, err := p.db.ExecContext(ctx, `DELETE FROM `+p.table+` WHERE `+where, args...); err != nil {
		p.onError("sweep", err)
	}
}

var _ SessionStore = (*PostgresStore)(nil)

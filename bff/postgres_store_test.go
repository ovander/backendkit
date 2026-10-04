package bff

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // the test's database/sql driver; the package itself imports none

	"github.com/ovander/backendkit/socrate"
)

var testKey = bytes.Repeat([]byte{7}, 32)

// pgStore opens TEST_DATABASE_URL and returns a store on a table unique to
// the test, dropped at the end.
func pgStore(t *testing.T, idle, absolute time.Duration) (*PostgresStore, *sql.DB) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		if os.Getenv("CI") != "" {
			t.Fatal("TEST_DATABASE_URL must be set in CI: the PostgresStore tests need a PostgreSQL database")
		}
		t.Skip("TEST_DATABASE_URL not set: the PostgresStore tests need a PostgreSQL database")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	table := fmt.Sprintf("bff_test_%d", time.Now().UnixNano())
	s, err := NewPostgresStore(context.Background(), db, testKey, idle, absolute,
		WithPostgresTable(table), WithPostgresErrorHandler(func(op string, err error) { t.Errorf("%s: %v", op, err) }))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec("DROP TABLE IF EXISTS " + table) })
	return s, db
}

func testSession(id string, now time.Time) *Session {
	return NewSession(id, "csrf-"+id,
		&socrate.TokenSet{AccessToken: "access-" + id, RefreshToken: "refresh-" + id, ExpiresIn: 900},
		UserInfo{Sub: "42", Email: "ada@example.test", Roles: []string{"user"}}, now)
}

func TestPostgresStore_SurvivesARestart(t *testing.T) {
	s, db := pgStore(t, time.Hour, 8*time.Hour)
	s.Put(testSession("s1", time.Now()))

	// A new store on the same table, as after a restart.
	again, err := NewPostgresStore(context.Background(), db, testKey, time.Hour, 8*time.Hour, WithPostgresTable(s.table))
	if err != nil {
		t.Fatal(err)
	}
	got, ok := again.Get("s1")
	if !ok {
		t.Fatal("session lost across a restart")
	}
	if got.AccessToken() != "access-s1" || got.RefreshToken() != "refresh-s1" || !got.MatchCSRF("csrf-s1") ||
		got.User().Sub != "42" || got.User().Email != "ada@example.test" {
		t.Fatalf("round trip lost data: %s", got)
	}
	if _, ok := again.Get("unknown"); ok {
		t.Fatal("unknown id found")
	}
}

func TestPostgresStore_TokensAreEncryptedAtRest(t *testing.T) {
	s, db := pgStore(t, time.Hour, 0)
	s.Put(testSession("s2", time.Now()))
	var raw []byte
	if err := db.QueryRow("SELECT data FROM " + s.table + " WHERE id = 's2'").Scan(&raw); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"access-s2", "refresh-s2", "csrf-s2", "ada@example.test"} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("%q stored in clear", secret)
		}
	}
	// Another key cannot read it, and the data cannot be moved to another id.
	other, err := NewPostgresStore(context.Background(), db, bytes.Repeat([]byte{8}, 32), time.Hour, 0,
		WithPostgresTable(s.table), WithPostgresErrorHandler(func(string, error) {}))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := other.Get("s2"); ok {
		t.Fatal("read with the wrong key")
	}
	if _, err := db.Exec("INSERT INTO " + s.table + " SELECT 'moved', data, created_at, last_seen FROM " + s.table + " WHERE id = 's2'"); err != nil {
		t.Fatal(err)
	}
	s.onError = func(string, error) {}
	if _, ok := s.Get("moved"); ok {
		t.Fatal("ciphertext accepted under another session id")
	}
}

// Logout wipes the data, and a request racing it cannot re-create the session.
func TestPostgresStore_DeleteIsFinal(t *testing.T) {
	s, db := pgStore(t, time.Hour, 0)
	sess := testSession("s3", time.Now())
	s.Put(sess)
	s.Delete("s3")
	if _, ok := s.Get("s3"); ok {
		t.Fatal("deleted session still readable")
	}
	sess.Touch(time.Now())
	s.Put(sess) // the racing touch
	if _, ok := s.Get("s3"); ok {
		t.Fatal("Put re-created a deleted session")
	}
	var n int
	_ = db.QueryRow("SELECT length(data) FROM " + s.table + " WHERE id = 's3'").Scan(&n)
	if n != 0 {
		t.Fatalf("deleted session kept %d bytes of data", n)
	}
}

func TestPostgresStore_ExpiryAndSweep(t *testing.T) {
	s, db := pgStore(t, 30*time.Minute, 8*time.Hour)
	base := time.Now()
	s.now = func() time.Time { return base }
	s.Put(testSession("idle", base))
	s.Put(testSession("old", base.Add(-7*time.Hour)))
	s.Put(testSession("live", base))
	s.Put(testSession("gone", base))
	s.Delete("gone")

	s.now = func() time.Time { return base.Add(31 * time.Minute) }
	live := testSession("live", base)
	live.Touch(base.Add(25 * time.Minute))
	s.Put(live)
	if _, ok := s.Get("idle"); ok {
		t.Error("idle session not expired")
	}
	if _, ok := s.Get("live"); !ok {
		t.Error("touched session expired")
	}

	s.now = func() time.Time { return base.Add(70 * time.Minute) } // past "old"'s 8h and the tombstone TTL
	s.Sweep()
	var ids []string
	rows, err := db.Query("SELECT id FROM " + s.table + " ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		_ = rows.Scan(&id)
		ids = append(ids, id)
	}
	if strings.Join(ids, ",") != "" {
		t.Fatalf("after Sweep, rows = %v; want none (all idle, too old or deleted)", ids)
	}
}

// The Gateway works unchanged on top of the store.
func TestPostgresStore_WithGateway(t *testing.T) {
	s, _ := pgStore(t, time.Hour, 0)
	gw := &Gateway{Store: s, Cookie: CookieConfig{Name: "app_session", Secure: false}}
	s.Put(testSession("s5", time.Now()))
	req := httptest.NewRequest(http.MethodGet, "/api/x", nil)
	req.AddCookie(&http.Cookie{Name: "app_session", Value: "s5"})
	got, ok := gw.SessionFromRequest(req)
	if !ok || got.AccessToken() != "access-s5" {
		t.Fatalf("SessionFromRequest = %v, %v", got, ok)
	}
}

func TestNewPostgresStore_RefusesBadConfig(t *testing.T) {
	ctx := context.Background()
	if _, err := NewPostgresStore(ctx, nil, testKey, 0, 0); err == nil {
		t.Error("nil db accepted")
	}
	db, _ := sql.Open("pgx", "postgres://invalid")
	defer db.Close()
	if _, err := NewPostgresStore(ctx, db, []byte("short"), 0, 0); err == nil || !strings.Contains(err.Error(), "32 bytes") {
		t.Errorf("short key: %v", err)
	}
	if _, err := NewPostgresStore(ctx, db, testKey, 0, 0, WithPostgresTable("x; DROP TABLE users")); err == nil ||
		!strings.Contains(err.Error(), "invalid table name") {
		t.Errorf("bad table name: %v", err)
	}
}

// pgDB opens TEST_DATABASE_URL and returns a fresh table name, dropped at the
// end, for tests that create the table themselves.
func pgDB(t *testing.T) (*sql.DB, string) {
	t.Helper()
	s, db := pgStore(t, time.Hour, 8*time.Hour) // skips without TEST_DATABASE_URL
	table := s.table + "_managed"
	t.Cleanup(func() { _, _ = db.Exec("DROP TABLE IF EXISTS " + table) })
	return db, table
}

const managedTableDDL = `CREATE TABLE %s (
	id         text        PRIMARY KEY,
	data       bytea       NOT NULL,
	created_at timestamptz NOT NULL,
	last_seen  timestamptz NOT NULL,
	deleted_at timestamptz
)`

// With WithPostgresManagedSchema the store runs no DDL: on a table created by
// a migration (here without the index), sessions round-trip and no index
// appears; on a missing table it refuses to start and creates nothing.
func TestPostgresStore_ManagedSchema(t *testing.T) {
	db, table := pgDB(t)
	ctx := context.Background()

	if _, err := NewPostgresStore(ctx, db, testKey, time.Hour, 8*time.Hour,
		WithPostgresTable(table), WithPostgresManagedSchema()); err == nil {
		t.Fatal("a managed store started on a missing table")
	}
	var exists bool
	if err := db.QueryRow(`SELECT to_regclass($1) IS NOT NULL`, table).Scan(&exists); err != nil || exists {
		t.Fatalf("the managed store created its table (exists=%v, err=%v)", exists, err)
	}

	if _, err := db.Exec(fmt.Sprintf(managedTableDDL, table)); err != nil {
		t.Fatal(err)
	}
	s, err := NewPostgresStore(ctx, db, testKey, time.Hour, 8*time.Hour, WithPostgresTable(table),
		WithPostgresManagedSchema(), WithPostgresErrorHandler(func(op string, err error) { t.Errorf("%s: %v", op, err) }))
	if err != nil {
		t.Fatalf("managed store on an existing table: %v", err)
	}
	s.Put(testSession("m1", time.Now()))
	if got, ok := s.Get("m1"); !ok || got.RefreshToken() != "refresh-m1" {
		t.Fatalf("Get = %s, %v", got, ok)
	}
	s.Delete("m1")
	if _, ok := s.Get("m1"); ok {
		t.Fatal("deleted session still readable")
	}
	if err := db.QueryRow(`SELECT to_regclass($1) IS NOT NULL`, table+"_last_seen_idx").Scan(&exists); err != nil || exists {
		t.Fatalf("the managed store created the index (exists=%v, err=%v): it must run no DDL", exists, err)
	}
}

// A managed table the role cannot fully use fails at start-up, naming the
// missing privilege, instead of at the first sign-in; so does a table without
// the expected columns.
func TestPostgresStore_ManagedSchemaChecksTheTable(t *testing.T) {
	db, table := pgDB(t)
	ctx := context.Background()
	if _, err := db.Exec(fmt.Sprintf(managedTableDDL, table)); err != nil {
		t.Fatal(err)
	}
	// The owner may revoke its own privileges; has_table_privilege then says no.
	if _, err := db.Exec("REVOKE DELETE ON " + table + " FROM CURRENT_USER"); err != nil {
		t.Fatal(err)
	}
	_, err := NewPostgresStore(ctx, db, testKey, 0, 0, WithPostgresTable(table), WithPostgresManagedSchema())
	if err == nil || !strings.Contains(err.Error(), "DELETE") {
		t.Fatalf("missing DELETE privilege: %v, want a start-up error naming it", err)
	}

	if _, err := db.Exec("DROP TABLE " + table); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE " + table + " (id text PRIMARY KEY)"); err != nil {
		t.Fatal(err)
	}
	if _, err := NewPostgresStore(ctx, db, testKey, 0, 0, WithPostgresTable(table), WithPostgresManagedSchema()); err == nil {
		t.Fatal("a table without the store's columns was accepted")
	}
}

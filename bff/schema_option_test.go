package bff

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"strings"
	"testing"
	"time"
)

// captureLog redirects the standard logger for the duration of fn.
func captureLog(t *testing.T, fn func()) string {
	t.Helper()
	var buf bytes.Buffer
	prevOut, prevFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	defer func() { log.SetOutput(prevOut); log.SetFlags(prevFlags) }()
	fn()
	return buf.String()
}

// Without a schema option the stores still create their tables, as before,
// but warn; naming either option silences the warning; naming both is refused.
func TestSchemaOptions(t *testing.T) {
	_, db := pgStore(t, time.Hour, time.Hour)
	ctx := context.Background()
	table := func(prefix string) string {
		name := fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
		t.Cleanup(func() { _, _ = db.Exec("DROP TABLE IF EXISTS " + name) })
		return name
	}

	t.Run("session store", func(t *testing.T) {
		name := table("bff_test_schemaopt")
		out := captureLog(t, func() {
			if _, err := NewPostgresStore(ctx, db, testKey, time.Hour, 0, WithPostgresTable(name)); err != nil {
				t.Fatal(err)
			}
		})
		if !strings.Contains(out, "WithPostgresAutoSchema") || !strings.Contains(out, "WithPostgresManagedSchema") {
			t.Errorf("no warning without a schema option: %q", out)
		}
		out = captureLog(t, func() {
			if _, err := NewPostgresStore(ctx, db, testKey, time.Hour, 0, WithPostgresTable(name), WithPostgresAutoSchema()); err != nil {
				t.Fatal(err)
			}
		})
		if out != "" {
			t.Errorf("WithPostgresAutoSchema still warned: %q", out)
		}
		if _, err := NewPostgresStore(ctx, db, testKey, time.Hour, 0, WithPostgresTable(name),
			WithPostgresAutoSchema(), WithPostgresManagedSchema()); err == nil {
			t.Error("both schema options were accepted")
		}
	})

	t.Run("pending login store", func(t *testing.T) {
		name := table("bff_test_schemaopt_pending")
		out := captureLog(t, func() {
			if _, err := NewPostgresPendingLoginStore(ctx, db, testKey, 0, WithPendingLoginTable(name)); err != nil {
				t.Fatal(err)
			}
		})
		if !strings.Contains(out, "WithPendingLoginAutoSchema") {
			t.Errorf("no warning without a schema option: %q", out)
		}
		out = captureLog(t, func() {
			if _, err := NewPostgresPendingLoginStore(ctx, db, testKey, 0, WithPendingLoginTable(name), WithPendingLoginAutoSchema()); err != nil {
				t.Fatal(err)
			}
		})
		if out != "" {
			t.Errorf("WithPendingLoginAutoSchema still warned: %q", out)
		}
		if _, err := NewPostgresPendingLoginStore(ctx, db, testKey, 0, WithPendingLoginTable(name),
			WithPendingLoginAutoSchema(), WithPendingLoginManagedSchema()); err == nil {
			t.Error("both schema options were accepted")
		}
	})
}

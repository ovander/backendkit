package gormlogger_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
	glogger "gorm.io/gorm/logger"

	"github.com/ovander/backendkit/gormlogger"
)

func newLogger(buf *bytes.Buffer, level glogger.LogLevel) glogger.Interface {
	l := logrus.New()
	l.SetOutput(buf)
	l.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
	return gormlogger.New(logrus.NewEntry(l), level, 100*time.Millisecond, true)
}

func TestTrace_SlowQuery(t *testing.T) {
	var buf bytes.Buffer
	gl := newLogger(&buf, glogger.Warn)

	gl.Trace(context.Background(), time.Now().Add(-200*time.Millisecond), func() (string, int64) {
		return "SELECT 1", 1
	}, nil)

	if !strings.Contains(buf.String(), "slow sql query") {
		t.Errorf("expected slow sql query log, got: %s", buf.String())
	}
}

func TestTrace_SQLRedaction(t *testing.T) {
	var buf bytes.Buffer
	l := logrus.New()
	l.SetOutput(&buf)
	l.SetFormatter(&logrus.TextFormatter{DisableTimestamp: true})
	gl := gormlogger.New(logrus.NewEntry(l), glogger.Warn, 100*time.Millisecond, true,
		gormlogger.WithSQLRedaction())

	// A slow query carrying a sensitive value in the interpolated SQL.
	gl.Trace(context.Background(), time.Now().Add(-200*time.Millisecond), func() (string, int64) {
		return "SELECT * FROM users WHERE email = 'secret@example.com'", 1
	}, nil)

	out := buf.String()
	if strings.Contains(out, "secret@example.com") {
		t.Errorf("redaction failed: SQL value leaked into log: %s", out)
	}
	if !strings.Contains(out, "[redacted]") {
		t.Errorf("expected [redacted] placeholder, got: %s", out)
	}
	if !strings.Contains(out, "slow sql query") {
		t.Errorf("expected the query to still be logged (timing/caller), got: %s", out)
	}
}

func TestTrace_ErrorLogged(t *testing.T) {
	var buf bytes.Buffer
	gl := newLogger(&buf, glogger.Error)

	gl.Trace(context.Background(), time.Now(), func() (string, int64) {
		return "SELECT boom", 0
	}, errors.New("db exploded"))

	if !strings.Contains(buf.String(), "sql error") {
		t.Errorf("expected sql error log, got: %s", buf.String())
	}
}

func TestTrace_IgnoresNotFound(t *testing.T) {
	var buf bytes.Buffer
	gl := newLogger(&buf, glogger.Error)

	gl.Trace(context.Background(), time.Now(), func() (string, int64) {
		return "SELECT 1", 0
	}, gorm.ErrRecordNotFound)

	// ignoreNotFound=true → should NOT log an error line
	if strings.Contains(buf.String(), "sql error") {
		t.Errorf("should not log error for ErrRecordNotFound: %s", buf.String())
	}
}

func TestTrace_SilentMode(t *testing.T) {
	var buf bytes.Buffer
	gl := newLogger(&buf, glogger.Silent)

	gl.Trace(context.Background(), time.Now().Add(-200*time.Millisecond), func() (string, int64) {
		return "SELECT 1", 1
	}, nil)

	if buf.Len() != 0 {
		t.Errorf("silent mode should produce no output, got: %s", buf.String())
	}
}

func TestLogMode_ReturnsNewInstance(t *testing.T) {
	var buf bytes.Buffer
	gl := newLogger(&buf, glogger.Silent)
	gl2 := gl.LogMode(glogger.Info)
	if gl2 == gl {
		t.Error("LogMode should return a new instance")
	}
}

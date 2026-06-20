// Package gormlogger provides a GORM logger implementation that routes SQL
// output through a logrus.Entry.
//
// Usage:
//
//	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
//	    Logger: gormlogger.New(
//	        logrus.WithField("component", "db"),
//	        glogger.Warn,
//	        500*time.Millisecond,
//	        true,
//	    ),
//	})
package gormlogger

import (
	"context"
	"errors"
	"time"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
	glogger "gorm.io/gorm/logger"
	"gorm.io/gorm/utils"
)

// GormLogger routes GORM's SQL output through a logrus.Entry.
//
// Recommended settings:
//
//	dev:        level=Info,  slowThreshold=200ms, ignoreNotFound=true
//	production: level=Warn,  slowThreshold=500ms, ignoreNotFound=true, WithSQLRedaction()
//
// In production add WithSQLRedaction() so interpolated SQL values (which may
// contain PII or secrets) are kept out of logs.
type GormLogger struct {
	entry          *logrus.Entry
	level          glogger.LogLevel
	slowThreshold  time.Duration
	ignoreNotFound bool
	redactSQL      bool
}

// Option configures optional GormLogger behaviour. Pass options to New.
type Option func(*GormLogger)

// WithSQLRedaction omits the SQL statement from log records — logging
// `sql: "[redacted]"` alongside the usual timing, row count, and caller. GORM
// hands the logger SQL with bound parameter values already interpolated, which
// can contain PII or secrets; enable this in production so those values are never
// written to logs.
func WithSQLRedaction() Option {
	return func(l *GormLogger) { l.redactSQL = true }
}

// New returns a glogger.Interface backed by the given logrus Entry.
//   - level: minimum level at which to emit log records (Silent/Error/Warn/Info)
//   - slowThreshold: queries slower than this are logged at Warn; set 0 to disable
//   - ignoreNotFound: when true, ErrRecordNotFound produces a Debug line instead of Error
//
// Optional behaviour (e.g. SQL redaction) is configured via opts; see
// WithSQLRedaction. Passing no options preserves the historical behaviour, so
// existing four-argument calls continue to compile and behave unchanged.
func New(entry *logrus.Entry, level glogger.LogLevel, slowThreshold time.Duration, ignoreNotFound bool, opts ...Option) glogger.Interface {
	l := &GormLogger{
		entry:          entry,
		level:          level,
		slowThreshold:  slowThreshold,
		ignoreNotFound: ignoreNotFound,
	}
	for _, opt := range opts {
		opt(l)
	}
	return l
}

// LogMode returns a copy of the logger configured at the given level.
func (l *GormLogger) LogMode(level glogger.LogLevel) glogger.Interface {
	clone := *l
	clone.level = level
	return &clone
}

// Info logs a message at info level when the configured level permits it.
func (l *GormLogger) Info(ctx context.Context, s string, args ...interface{}) {
	if l.level >= glogger.Info {
		l.entry.WithContext(ctx).Infof(s, args...)
	}
}

// Warn logs a message at warn level when the configured level permits it.
func (l *GormLogger) Warn(ctx context.Context, s string, args ...interface{}) {
	if l.level >= glogger.Warn {
		l.entry.WithContext(ctx).Warnf(s, args...)
	}
}

func (l *GormLogger) Error(ctx context.Context, s string, args ...interface{}) {
	if l.level >= glogger.Error {
		l.entry.WithContext(ctx).Errorf(s, args...)
	}
}

// Trace logs a single SQL statement with its duration and row count, applying
// the slow-query and not-found handling configured on the logger.
func (l *GormLogger) Trace(ctx context.Context, begin time.Time, fc func() (string, int64), err error) {
	if l.level == glogger.Silent {
		return
	}

	elapsed := time.Since(begin)
	sql, rows := fc()
	if l.redactSQL {
		sql = "[redacted]"
	}

	fields := logrus.Fields{
		"elapsed_ms": elapsed.Milliseconds(),
		"rows":       rows,
		"sql":        sql,
		"caller":     utils.FileWithLineNum(),
	}
	entry := l.entry.WithContext(ctx).WithFields(fields)

	switch {
	case err != nil:
		if l.ignoreNotFound && errors.Is(err, gorm.ErrRecordNotFound) {
			if l.level >= glogger.Info {
				entry.Debug("sql not found")
			}
			return
		}
		if l.level >= glogger.Error {
			entry.WithError(err).Error("sql error")
		}

	case l.slowThreshold > 0 && elapsed > l.slowThreshold:
		if l.level >= glogger.Warn {
			entry.WithField("slow_threshold_ms", l.slowThreshold.Milliseconds()).
				Warn("slow sql query")
		}

	default:
		if l.level >= glogger.Info {
			entry.Debug("sql query")
		}
	}
}

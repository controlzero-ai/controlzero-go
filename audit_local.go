package controlzero

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"gopkg.in/natefinch/lumberjack.v2"
)

// LocalAuditLogger writes JSON Lines audit entries to a local file with
// optional size-based rotation via lumberjack.
//
// Why lumberjack?
//
//	It's the boring choice for log rotation in Go. Single dependency, mature,
//	zero ceremony, plays well with the standard io.Writer interface.
type LocalAuditLogger struct {
	logPath  string
	format   string // "json" or "pretty"
	writer   *lumberjack.Logger
	fallback bool
	mu       sync.Mutex
}

// LocalAuditOptions configures the local audit sink.
type LocalAuditOptions struct {
	LogPath        string
	MaxSizeMB      int    // size-based rotation; 0 = no rotation
	MaxBackups     int    // how many rotated files to keep
	MaxAgeDays     int    // delete rotated files older than N days
	Compress       bool   // gzip rotated files
	Format         string // "json" (default) or "pretty"
}

// NewLocalAuditLogger constructs a sink. If the path is unwritable, all
// subsequent writes go to stderr instead.
func NewLocalAuditLogger(opts LocalAuditOptions) *LocalAuditLogger {
	if opts.LogPath == "" {
		opts.LogPath = "./controlzero.log"
	}
	if opts.Format == "" {
		opts.Format = "json"
	}

	l := &LocalAuditLogger{
		logPath: opts.LogPath,
		format:  opts.Format,
	}

	// Make sure parent directory exists
	parent := filepath.Dir(opts.LogPath)
	if parent != "" && parent != "." {
		if err := os.MkdirAll(parent, 0o755); err != nil {
			fmt.Fprintf(os.Stderr,
				"controlzero: cannot create log directory %s (%v), falling back to stderr.\n",
				parent, err)
			l.fallback = true
			return l
		}
	}

	// Touch-test write access
	f, err := os.OpenFile(opts.LogPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		fmt.Fprintf(os.Stderr,
			"controlzero: cannot write to %s (%v), falling back to stderr.\n",
			opts.LogPath, err)
		l.fallback = true
		return l
	}
	_ = f.Close()

	l.writer = &lumberjack.Logger{
		Filename:   opts.LogPath,
		MaxSize:    opts.MaxSizeMB,
		MaxBackups: opts.MaxBackups,
		MaxAge:     opts.MaxAgeDays,
		Compress:   opts.Compress,
	}

	return l
}

// Log writes a single audit entry.
func (l *LocalAuditLogger) Log(entry map[string]any) {
	line := l.formatEntry(entry)
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.fallback || l.writer == nil {
		fmt.Fprintln(os.Stderr, line)
		return
	}

	if _, err := l.writer.Write([]byte(line + "\n")); err != nil {
		// Disk filled up or path became unwritable mid-run. Drop to stderr
		// for the rest of the process so we never lose audit lines silently.
		fmt.Fprintf(os.Stderr,
			"controlzero: write failed (%v), falling back to stderr.\n", err)
		l.fallback = true
		fmt.Fprintln(os.Stderr, line)
	}
}

func (l *LocalAuditLogger) formatEntry(entry map[string]any) string {
	record := make(map[string]any, len(entry)+1)
	record["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	for k, v := range entry {
		record[k] = v
	}

	if l.format == "pretty" {
		return fmt.Sprintf("%v | %v | %v | %v",
			record["ts"],
			fmtVal(record["decision"]),
			fmtVal(record["tool"]),
			fmtVal(record["reason"]),
		)
	}

	b, err := json.Marshal(record)
	if err != nil {
		return fmt.Sprintf(`{"ts":%q,"error":"json marshal failed: %v"}`, record["ts"], err)
	}
	return string(b)
}

func fmtVal(v any) string {
	if v == nil {
		return "?"
	}
	return fmt.Sprintf("%v", v)
}

// Close flushes and closes the underlying file. Safe to call multiple times.
func (l *LocalAuditLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.writer != nil {
		err := l.writer.Close()
		l.writer = nil
		return err
	}
	return nil
}

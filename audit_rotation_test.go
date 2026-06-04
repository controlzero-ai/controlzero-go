package controlzero

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestLocalAuditDefaultMaxBackupsBounded verifies that leaving MaxBackups at
// the zero value does NOT produce lumberjack's "keep all backups" behavior.
// Before #890 a 0 meant unbounded retention of rotated files. The sink now
// coerces 0 to defaultMaxBackups so the rotated set stays bounded.
func TestLocalAuditDefaultMaxBackupsBounded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	// MaxSizeMB: 1 (smallest size lumberjack rotates on) and MaxBackups: 0
	// (the unbounded footgun) -- the sink must bound it for us.
	l := NewLocalAuditLogger(LocalAuditOptions{
		LogPath:    path,
		MaxSizeMB:  1,
		MaxBackups: 0,
	})
	defer l.Close()

	if l.writer.MaxBackups != defaultMaxBackups {
		t.Fatalf("MaxBackups: want coerced default %d, got %d",
			defaultMaxBackups, l.writer.MaxBackups)
	}

	// Write well past several 1 MB rotations and confirm the on-disk backup
	// set never exceeds the bounded default.
	big := strings.Repeat("x", 4096)
	for i := 0; i < 4000; i++ { // ~16 MB total -> many 1 MB rolls
		l.Log(map[string]any{"decision": "allow", "tool": "t", "reason": big})
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	backups := 0
	base := filepath.Base(path)
	for _, e := range entries {
		if e.Name() != base && strings.HasPrefix(e.Name(), strings.TrimSuffix(base, ".log")) {
			backups++
		}
	}
	if backups > defaultMaxBackups {
		t.Fatalf("rotated backup count %d exceeds bounded default %d", backups, defaultMaxBackups)
	}
}

// TestLocalAuditDefaultMaxSizeBounded verifies that leaving MaxSizeMB at 0
// applies the bounded default rather than lumberjack's "no size limit".
func TestLocalAuditDefaultMaxSizeBounded(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	l := NewLocalAuditLogger(LocalAuditOptions{LogPath: path})
	defer l.Close()

	if l.writer.MaxSize != defaultMaxSizeMB {
		t.Fatalf("MaxSize: want coerced default %d, got %d", defaultMaxSizeMB, l.writer.MaxSize)
	}
	if l.writer.MaxBackups != defaultMaxBackups {
		t.Fatalf("MaxBackups: want coerced default %d, got %d", defaultMaxBackups, l.writer.MaxBackups)
	}
}

// TestLocalAuditExplicitMaxBackupsHonored verifies an explicit non-zero
// MaxBackups is passed through unchanged (no surprise coercion).
func TestLocalAuditExplicitMaxBackupsHonored(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")

	l := NewLocalAuditLogger(LocalAuditOptions{
		LogPath:    path,
		MaxSizeMB:  5,
		MaxBackups: 3,
	})
	defer l.Close()

	if l.writer.MaxBackups != 3 {
		t.Fatalf("explicit MaxBackups not honored: got %d", l.writer.MaxBackups)
	}
	if l.writer.MaxSize != 5 {
		t.Fatalf("explicit MaxSize not honored: got %d", l.writer.MaxSize)
	}
}

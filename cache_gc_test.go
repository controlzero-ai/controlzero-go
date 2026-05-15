package controlzero

import (
	"os"
	"path/filepath"
	"testing"
)

// T104 regression: stale cache GC on key rotation.
//
// an enterprise customer (Korea) 2026-05-12: rotated his api_key from
// cz_live_566b... to cz_live_1af8.... The old key's cache files
// lingered for 25 days next to the new bootstrap. T104 removes any
// cache files whose scope does NOT match the active key on the next
// fresh bootstrap fetch.

func writeTriplet(t *testing.T, dir, scope string) {
	t.Helper()
	for _, name := range []string{
		"bootstrap-" + scope + ".json",
		"bundle-" + scope + ".bin",
		"bundle-" + scope + ".meta",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
}

func setupSandboxHome(t *testing.T) string {
	t.Helper()
	sandbox := t.TempDir()
	t.Setenv("HOME", sandbox)
	cacheDir := filepath.Join(sandbox, ".controlzero", "cache")
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		t.Fatalf("mkdir cache: %v", err)
	}
	return cacheDir
}

func TestGcStaleCache_RemovesRotatedKeys(t *testing.T) {
	cacheDir := setupSandboxHome(t)
	writeTriplet(t, cacheDir, "cz_live_566b")
	writeTriplet(t, cacheDir, "cz_live_1af8")

	removed := gcStaleCache("cz_live_1af8fd9bcafe")

	if removed != 3 {
		t.Fatalf("expected 3 removed, got %d", removed)
	}
	for _, name := range []string{
		"bootstrap-cz_live_566b.json",
		"bundle-cz_live_566b.bin",
		"bundle-cz_live_566b.meta",
	} {
		if _, err := os.Stat(filepath.Join(cacheDir, name)); !os.IsNotExist(err) {
			t.Errorf("expected %s removed, still present", name)
		}
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "bootstrap-cz_live_1af8.json")); err != nil {
		t.Errorf("active bootstrap unexpectedly removed: %v", err)
	}
}

func TestGcStaleCache_NoopWhenOnlyActiveKey(t *testing.T) {
	cacheDir := setupSandboxHome(t)
	writeTriplet(t, cacheDir, "cz_live_1af8")

	if removed := gcStaleCache("cz_live_1af8fd9bcafe"); removed != 0 {
		t.Fatalf("expected 0 removed, got %d", removed)
	}
}

func TestGcStaleCache_LeavesUserFilesAlone(t *testing.T) {
	cacheDir := setupSandboxHome(t)
	writeTriplet(t, cacheDir, "cz_live_oldd")
	if err := os.WriteFile(filepath.Join(cacheDir, "README.txt"), []byte("notes"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cacheDir, "s3_copy.py"), []byte("# user"), 0o600); err != nil {
		t.Fatal(err)
	}

	removed := gcStaleCache("cz_live_acti")
	if removed != 3 {
		t.Fatalf("expected 3 removed, got %d", removed)
	}
	for _, name := range []string{"README.txt", "s3_copy.py"} {
		if _, err := os.Stat(filepath.Join(cacheDir, name)); err != nil {
			t.Errorf("user file %s unexpectedly removed: %v", name, err)
		}
	}
}

func TestGcStaleCache_OrphanBundleBin(t *testing.T) {
	cacheDir := setupSandboxHome(t)
	orphan := filepath.Join(cacheDir, "bundle-cz_live_orph.bin")
	if err := os.WriteFile(orphan, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if removed := gcStaleCache("cz_live_acti"); removed != 1 {
		t.Fatalf("expected 1 removed, got %d", removed)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Errorf("expected orphan removed, still present")
	}
}

func TestGcStaleCache_EmptyKeyIsNoop(t *testing.T) {
	cacheDir := setupSandboxHome(t)
	writeTriplet(t, cacheDir, "whatever____")
	if removed := gcStaleCache(""); removed != 0 {
		t.Fatalf("expected 0 removed, got %d", removed)
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "bootstrap-whatever____.json")); err != nil {
		t.Errorf("file unexpectedly removed on empty key: %v", err)
	}
}

func TestGcStaleCache_SkipsPlantedDirectory(t *testing.T) {
	// A directory named bundle-<scope>.bin must not be passed to os.Remove
	// or it would error. entry.IsDir() guards against that.
	cacheDir := setupSandboxHome(t)
	if err := os.MkdirAll(filepath.Join(cacheDir, "bundle-cz_live_dir_.bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTriplet(t, cacheDir, "cz_live_oldd")

	removed := gcStaleCache("cz_live_acti")
	if removed != 3 {
		t.Fatalf("expected 3 removed (file triplet only), got %d", removed)
	}
	if _, err := os.Stat(filepath.Join(cacheDir, "bundle-cz_live_dir_.bin")); err != nil {
		t.Errorf("planted directory unexpectedly removed: %v", err)
	}
}

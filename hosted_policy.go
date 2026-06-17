package controlzero

// Hosted-mode policy orchestration (parity with Python/Node SDKs).
//
// Flow on New(WithAPIKey(...)) when no local policy is set:
//
//  1. loadHostedPolicy() is invoked.
//  2. If no bootstrap cached, fetchBootstrap() hits GET /v1/sdk/bootstrap
//     to retrieve project encryption + signing keys. Cached to disk.
//  3. pullBundle() hits GET /v1/sdk/policies/pull with the cached ETag
//     if one exists.
//  4. On 200: the signed bundle is parsed + verified + decrypted via
//     internal/bundle.Parse. Success path caches the bundle bytes.
//  5. On 304: the cached bundle is parsed + verified using cached keys.
//  6. On 401/403: HostedAuthError (permanent; user supplied bad key).
//  7. On any other failure: fall back to cached bundle if present (with
//     a warning), otherwise HostedBootstrapError (fail closed).
//
// Cache layout under ~/.controlzero/cache/:
//
//   - bootstrap-<prefix>.json -- JSON dict with keys + metadata
//   - bundle-<prefix>.bin     -- raw signed bundle bytes
//   - bundle-<prefix>.meta    -- ETag + checksum for conditional fetches

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"controlzero.ai/sdk/go/internal/bundle"
)

// recommendedSDKNudgeOnce throttles the non-breaking upgrade nudge to one
// stderr line per process, regardless of how many bundles load or how often
// the policy refreshes. The nudge is purely informational -- it never changes
// enforcement and never errors.
var recommendedSDKNudgeOnce sync.Once

// maybeWarnRecommendedSDK prints ONE non-fatal stderr warning per process if
// the hosted bundle's metadata carries a recommended_sdk_version newer than
// the running Version. No-op when the field is absent (back-compat) or when
// the SDK is already at/above the recommendation.
//
// recommended_sdk_version is the SOFT signal: enforcement/audit fixes ship in
// the SDK, so customers on old versions keep hitting fixed bugs until they
// upgrade. The nudge points them at `controlzero update`. Distinct from the
// HARD min_sdk_version floor (gh#602), which refuses to load the bundle.
func maybeWarnRecommendedSDK(payload map[string]any) {
	r := bundle.CheckRecommendedSDKVersion(payload, Version)
	if !r.Behind {
		return
	}
	recommendedSDKNudgeOnce.Do(func() {
		fmt.Fprintf(os.Stderr,
			"controlzero %s is behind the recommended %s; run 'controlzero update'\n",
			r.Actual, r.Recommended)
	})
}

const (
	defaultAPIURL    = "https://api.controlzero.ai"
	bootstrapTimeout = 5 * time.Second
	pullTimeout      = 5 * time.Second
	maxBundleBytes   = 16 * 1024 * 1024
)

// GetAPIURL resolves the Control Zero API base URL from env var, or
// falls back to the SaaS default.
func GetAPIURL() string {
	raw := os.Getenv("CONTROLZERO_API_URL")
	if raw == "" {
		raw = defaultAPIURL
	}
	return strings.TrimRight(raw, "/")
}

// bootstrapKeys holds the project keys returned by /v1/sdk/bootstrap.
type bootstrapKeys struct {
	ProjectID     string
	OrgID         string
	EncryptionKey []byte // 32 bytes
	SigningPubkey []byte // 32 bytes, raw
	KeyVersion    int
}

type cachedBundle struct {
	Bytes    []byte
	ETag     string
	Checksum string
}

func cacheDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	d := filepath.Join(home, ".controlzero", "cache")
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", err
	}
	return d, nil
}

func keyScope(apiKey string) string {
	if apiKey == "" {
		return "unknown"
	}
	n := 12
	if len(apiKey) < n {
		n = len(apiKey)
	}
	scope := apiKey[:n]
	scope = strings.ReplaceAll(scope, "/", "_")
	scope = strings.ReplaceAll(scope, ".", "_")
	return scope
}

func bootstrapCachePath(apiKey string) (string, error) {
	d, err := cacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(d, "bootstrap-"+keyScope(apiKey)+".json"), nil
}

func loadCachedBootstrap(apiKey string) *bootstrapKeys {
	p, err := bootstrapCachePath(apiKey)
	if err != nil {
		return nil
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	var j struct {
		ProjectID               string `json:"project_id"`
		OrgID                   string `json:"org_id"`
		ProjectEncryptionKeyB64 string `json:"project_encryption_key_b64"`
		SigningPubkeyHex        string `json:"signing_pubkey_hex"`
		KeyVersion              int    `json:"key_version"`
	}
	if err := json.Unmarshal(raw, &j); err != nil {
		return nil
	}
	enc, err := base64.StdEncoding.DecodeString(j.ProjectEncryptionKeyB64)
	if err != nil {
		return nil
	}
	pub, err := hex.DecodeString(j.SigningPubkeyHex)
	if err != nil {
		return nil
	}
	return &bootstrapKeys{
		ProjectID:     j.ProjectID,
		OrgID:         j.OrgID,
		EncryptionKey: enc,
		SigningPubkey: pub,
		KeyVersion:    j.KeyVersion,
	}
}

func saveCachedBootstrap(apiKey string, k *bootstrapKeys) error {
	p, err := bootstrapCachePath(apiKey)
	if err != nil {
		return err
	}
	j := map[string]any{
		"project_id":                 k.ProjectID,
		"org_id":                     k.OrgID,
		"project_encryption_key_b64": base64.StdEncoding.EncodeToString(k.EncryptionKey),
		"signing_pubkey_hex":         hex.EncodeToString(k.SigningPubkey),
		"key_version":                k.KeyVersion,
	}
	raw, _ := json.MarshalIndent(j, "", "  ")
	return os.WriteFile(p, raw, 0o600)
}

func fetchBootstrap(ctx context.Context, apiKey, apiURL string) (*bootstrapKeys, error) {
	base := strings.TrimRight(apiURL, "/")
	if base == "" {
		base = GetAPIURL()
	}

	ctx, cancel := context.WithTimeout(ctx, bootstrapTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/sdk/bootstrap", nil)
	if err != nil {
		return nil, &HostedBootstrapError{Msg: fmt.Sprintf("bootstrap request build failed: %v", err)}
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, &HostedBootstrapError{Msg: fmt.Sprintf("bootstrap request failed: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, newHostedAuthError(body, "")
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 500))
		return nil, &HostedBootstrapError{Msg: fmt.Sprintf("bootstrap returned HTTP %d: %s", resp.StatusCode, string(body))}
	}

	var j struct {
		ProjectID               string `json:"project_id"`
		OrgID                   string `json:"org_id"`
		ProjectEncryptionKeyB64 string `json:"project_encryption_key_b64"`
		SigningPubkeyHex        string `json:"signing_pubkey_hex"`
		KeyVersion              int    `json:"key_version"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&j); err != nil {
		return nil, &HostedBootstrapError{Msg: fmt.Sprintf("bootstrap response malformed: %v", err)}
	}
	enc, err := base64.StdEncoding.DecodeString(j.ProjectEncryptionKeyB64)
	if err != nil {
		return nil, &HostedBootstrapError{Msg: fmt.Sprintf("bad encryption key: %v", err)}
	}
	pub, err := hex.DecodeString(j.SigningPubkeyHex)
	if err != nil {
		return nil, &HostedBootstrapError{Msg: fmt.Sprintf("bad signing pubkey: %v", err)}
	}
	return &bootstrapKeys{
		ProjectID:     j.ProjectID,
		OrgID:         j.OrgID,
		EncryptionKey: enc,
		SigningPubkey: pub,
		KeyVersion:    j.KeyVersion,
	}, nil
}

func getOrFetchBootstrap(ctx context.Context, apiKey, apiURL string) (*bootstrapKeys, error) {
	if c := loadCachedBootstrap(apiKey); c != nil {
		return c, nil
	}
	k, err := fetchBootstrap(ctx, apiKey, apiURL)
	if err != nil {
		return nil, err
	}
	_ = saveCachedBootstrap(apiKey, k)
	// T104 (2026-05-12, customer report): GC cache files belonging to rotated
	// keys. Only fires on a fresh fetch because that's when the active
	// key may have just changed; cache hits skip GC.
	if removed := gcStaleCache(apiKey); removed > 0 {
		fmt.Fprintf(os.Stderr,
			"controlzero: removed %d stale cache file(s) from rotated keys\n",
			removed)
	}
	return k, nil
}

// gcStaleCache removes cache files belonging to api_keys other than the
// active one. Returns the count removed. Recognised cache families:
//
//	bootstrap-<scope>.json
//	bundle-<scope>.bin
//	bundle-<scope>.meta
//
// Stray user files (README, etc.) are NOT removed even if they sit in
// the cache directory. The cache dir is ours but we are conservative
// about what we delete.
func gcStaleCache(activeAPIKey string) int {
	if activeAPIKey == "" {
		return 0
	}
	d, err := cacheDir()
	if err != nil {
		return 0
	}
	activeScope := keyScope(activeAPIKey)
	entries, err := os.ReadDir(d)
	if err != nil {
		return 0
	}
	removed := 0
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		scope := extractScopeFromCacheFilename(entry.Name())
		if scope == "" || scope == activeScope {
			continue
		}
		if err := os.Remove(filepath.Join(d, entry.Name())); err == nil {
			removed++
		} else {
			// Parity with Python + Node SDKs: surface the failure on
			// stderr so an unreadable / read-only stale cache file is
			// visible to ops instead of silently surviving GC.
			fmt.Fprintf(os.Stderr,
				"controlzero: could not remove stale cache file %s: %v\n",
				entry.Name(), err)
		}
	}
	return removed
}

func extractScopeFromCacheFilename(name string) string {
	for _, pair := range []struct{ prefix, suffix string }{
		{"bootstrap-", ".json"},
		{"bundle-", ".bin"},
		{"bundle-", ".meta"},
	} {
		if strings.HasPrefix(name, pair.prefix) && strings.HasSuffix(name, pair.suffix) {
			return name[len(pair.prefix) : len(name)-len(pair.suffix)]
		}
	}
	return ""
}

func bundleCachePaths(apiKey string) (string, string, error) {
	d, err := cacheDir()
	if err != nil {
		return "", "", err
	}
	scope := keyScope(apiKey)
	return filepath.Join(d, "bundle-"+scope+".bin"), filepath.Join(d, "bundle-"+scope+".meta"), nil
}

func loadCachedBundle(apiKey string) *cachedBundle {
	bin, meta, err := bundleCachePaths(apiKey)
	if err != nil {
		return nil
	}
	b, err := os.ReadFile(bin)
	if err != nil {
		return nil
	}
	m, err := os.ReadFile(meta)
	if err != nil {
		return nil
	}
	var j struct {
		ETag     string `json:"etag"`
		Checksum string `json:"checksum"`
	}
	if err := json.Unmarshal(m, &j); err != nil {
		return nil
	}
	return &cachedBundle{Bytes: b, ETag: j.ETag, Checksum: j.Checksum}
}

func saveCachedBundle(apiKey string, blob []byte, etag string) error {
	bin, meta, err := bundleCachePaths(apiKey)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(blob)
	m, _ := json.MarshalIndent(map[string]any{
		"etag":     etag,
		"checksum": hex.EncodeToString(sum[:]),
	}, "", "  ")
	if err := os.WriteFile(bin, blob, 0o600); err != nil {
		return err
	}
	return os.WriteFile(meta, m, 0o600)
}

// pullBundle returns (blob, etag, nil) on 200, (nil, "", nil) on 304,
// or a typed error. Caller must use the cached bundle on (nil, "", nil).
func pullBundle(ctx context.Context, apiKey, apiURL, cachedETag string) ([]byte, string, error) {
	base := strings.TrimRight(apiURL, "/")
	if base == "" {
		base = GetAPIURL()
	}

	ctx, cancel := context.WithTimeout(ctx, pullTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/v1/sdk/policies/pull", nil)
	if err != nil {
		return nil, "", &HostedBootstrapError{Msg: fmt.Sprintf("pull request build failed: %v", err)}
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	if cachedETag != "" {
		req.Header.Set("If-None-Match", cachedETag)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, "", &HostedBootstrapError{Msg: fmt.Sprintf("bundle pull failed: %v", err)}
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotModified {
		return nil, "", nil
	}
	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return nil, "", newHostedAuthError(body, "during bundle pull")
	}
	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 500))
		return nil, "", &HostedBootstrapError{
			Msg: fmt.Sprintf("bundle pull returned HTTP %d: %s", resp.StatusCode, string(body)),
		}
	}
	blob, err := io.ReadAll(io.LimitReader(resp.Body, maxBundleBytes+1))
	if err != nil {
		return nil, "", &HostedBootstrapError{Msg: fmt.Sprintf("bundle read failed: %v", err)}
	}
	if len(blob) > maxBundleBytes {
		return nil, "", &HostedBootstrapError{Msg: "bundle exceeds size cap"}
	}
	etag := resp.Header.Get("ETag")
	if etag == "" {
		sum := sha256.Sum256(blob)
		etag = hex.EncodeToString(sum[:])[:32]
	}
	return blob, etag, nil
}

// loadHostedPolicy fetches + verifies + decrypts + translates the
// project's active policy. Returns the local-mode policy map and the
// parsed bundle (for metadata).
func loadHostedPolicy(ctx context.Context, apiKey, apiURL string) (map[string]any, *bundle.Parsed, error) {
	base := apiURL
	if base == "" {
		base = GetAPIURL()
	}

	keys, err := getOrFetchBootstrap(ctx, apiKey, base)
	if err != nil {
		return nil, nil, err
	}

	cached := loadCachedBundle(apiKey)
	var cachedETag string
	if cached != nil {
		cachedETag = cached.ETag
	}

	blob, etag, err := pullBundle(ctx, apiKey, base, cachedETag)
	if err != nil {
		if _, ok := err.(*HostedAuthError); ok {
			return nil, nil, err
		}
		if _, ok := err.(*HostedBootstrapError); ok {
			if cached != nil {
				fmt.Fprintf(os.Stderr,
					"controlzero: policy pull failed (%v), using cached bundle; "+
						"calls will be enforced against the last-known-good policy\n", err)
				return parseAndTranslate(ctx, cached.Bytes, keys, apiKey, base)
			}
		}
		return nil, nil, err
	}

	if blob == nil {
		// 304 Not Modified. Must have a cached bundle or we fail closed.
		if cached == nil {
			return nil, nil, &HostedBootstrapError{
				Msg: "backend returned 304 but no cached bundle is available; retry without cache",
			}
		}
		return parseAndTranslate(ctx, cached.Bytes, keys, apiKey, base)
	}

	parsed, err := bundle.Parse(blob, keys.EncryptionKey, keys.SigningPubkey,
		&bundle.ParseOptions{MaxBundleBytes: maxBundleBytes})
	if err != nil {
		// Possible key rotation: re-fetch once and retry.
		fmt.Fprintln(os.Stderr,
			"controlzero: bundle verification failed with cached keys; re-fetching bootstrap in case of key rotation")
		freshKeys, ferr := fetchBootstrap(ctx, apiKey, base)
		if ferr != nil {
			return nil, nil, wrapBundleErr(err)
		}
		_ = saveCachedBootstrap(apiKey, freshKeys)
		parsed, err = bundle.Parse(blob, freshKeys.EncryptionKey, freshKeys.SigningPubkey,
			&bundle.ParseOptions{MaxBundleBytes: maxBundleBytes})
		if err != nil {
			return nil, nil, wrapBundleErr(err)
		}
		keys = freshKeys
	}

	_ = saveCachedBundle(apiKey, blob, etag)

	// gh#602: gate on bundle.metadata.min_sdk_version BEFORE
	// translation so a stale SDK can never start applying selector
	// rules it does not understand.
	if r := bundle.CheckMinSDKVersion(parsed.Payload, Version); r.Refuse {
		return nil, nil, &BundleRequiresNewerSDKError{
			Required:       r.Required,
			Actual:         r.Actual,
			UpgradeCommand: "go get github.com/control-zero/controlzero@latest",
		}
	}

	// Non-breaking upgrade nudge: warn once per process if the bundle
	// recommends a newer SDK than we run. Never changes enforcement.
	maybeWarnRecommendedSDK(parsed.Payload)

	return bundle.TranslateToLocalPolicy(parsed.Payload), parsed, nil
}

func parseAndTranslate(
	ctx context.Context, blob []byte, keys *bootstrapKeys, apiKey, apiURL string,
) (map[string]any, *bundle.Parsed, error) {
	parsed, err := bundle.Parse(blob, keys.EncryptionKey, keys.SigningPubkey,
		&bundle.ParseOptions{MaxBundleBytes: maxBundleBytes})
	if err != nil {
		freshKeys, ferr := fetchBootstrap(ctx, apiKey, apiURL)
		if ferr != nil {
			return nil, nil, wrapBundleErr(err)
		}
		_ = saveCachedBootstrap(apiKey, freshKeys)
		parsed, err = bundle.Parse(blob, freshKeys.EncryptionKey, freshKeys.SigningPubkey,
			&bundle.ParseOptions{MaxBundleBytes: maxBundleBytes})
		if err != nil {
			return nil, nil, wrapBundleErr(err)
		}
	}
	// gh#602: cached / 304-served bundles get the same gate.
	if r := bundle.CheckMinSDKVersion(parsed.Payload, Version); r.Refuse {
		return nil, nil, &BundleRequiresNewerSDKError{
			Required:       r.Required,
			Actual:         r.Actual,
			UpgradeCommand: "go get github.com/control-zero/controlzero@latest",
		}
	}
	// Non-breaking upgrade nudge (cached / 304 path); warns once per process.
	maybeWarnRecommendedSDK(parsed.Payload)
	return bundle.TranslateToLocalPolicy(parsed.Payload), parsed, nil
}

// wrapBundleErr converts internal bundle errors to the SDK's public
// typed errors so callers can type-switch without importing internal/.
func wrapBundleErr(err error) error {
	if err == nil {
		return nil
	}
	if be, ok := err.(*bundle.FormatError); ok {
		return &BundleFormatError{Msg: be.Msg}
	}
	if be, ok := err.(*bundle.SignatureError); ok {
		return &BundleSignatureError{Msg: be.Msg}
	}
	return err
}

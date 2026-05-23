// Package credentialscanner is the Go SDK port of the credential
// leak scanner shipped in `crates/controlzero-core/src/credentials/
// scanner.rs` and mirrored in
// `sdks/python/controlzero/controlzero/_internal/credential_scanner.py`.
//
// Same YAML library, same four detection strategies (regex,
// regex_with_entropy, marker_block, regex_with_paired_token), same
// Shannon-entropy gate, same paired-token co-occurrence / label
// window semantics.
//
// Why a Go port of a Rust module: the Go SDK ships as a pure-Go
// module via the public proxy. Pulling in the Rust cdylib at install
// time would force per-platform builds and add a cgo dependency that
// breaks cross-compilation. Keeping a Go port loaded from the same
// YAML preserves the one-source-of-truth mandate (every SDK reads
// the same built_in.yaml) without breaking the pure-Go distribution
// path. The Rust FFI is still the in-process scanner for hosts that
// embed the cdylib directly; Go SDK consumers never see it.
//
// Public surface:
//
//	type Match struct { PatternID, Severity string; Start, End int }
//	func FromYAMLBytes(yaml []byte) (*Scanner, error)
//	func Default() (*Scanner, error)
//	func (s *Scanner) Scan(text string) []Match
//
// Match positions are byte offsets into the input pointing at capture
// group 1 for regex strategies, and at the [begin_marker_start,
// end_marker_end) span for marker-block strategies. On ASCII text
// byte offsets equal rune offsets; on multi-byte text the scanner
// reports byte offsets so the wire shape matches the Rust + Python
// implementations bit-for-bit.
package credentialscanner

import (
	_ "embed"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// defaultMaxBlockBytes is the per-occurrence byte cap for marker_block
// patterns that omit `max_block_bytes`. Matches the Rust scanner's
// DEFAULT_MAX_BLOCK_BYTES constant; 8192 bytes covers every PEM
// private key shape we ship and bounds worst-case scan time on a
// stray `BEGIN ` with no matching `END`.
const defaultMaxBlockBytes = 8192

// ErrUnknownPairedPattern is returned when a regex_with_paired_token
// row references a `paired_with` id that does not appear in the same
// YAML library. Authoring mistake; surfaces at compile time rather
// than as a silent scan miss in production.
var ErrUnknownPairedPattern = errors.New("credentialscanner: paired_with references unknown pattern")

//go:embed credentials_data/built_in.yaml
var defaultYAML []byte

// Match is one scanner hit. Mirrors the dict shape the Python scanner
// emits and the JSON shape the Rust FFI returns.
type Match struct {
	PatternID string
	Severity  string
	Start     int
	End       int
}

// regexRecord is the compiled per-pattern state for regex,
// regex_with_entropy, and regex_with_paired_token strategies.
type regexRecord struct {
	patternID             string
	regex                 *regexp.Regexp
	severity              string
	entropyMin            float64
	hasEntropyMin         bool
	minLength             int
	hasMinLength          bool
	pairedRegex           *regexp.Regexp
	pairedMaxByteDistance int
	hasPairedRegex        bool
	labelRequired         []string
	labelByteWindow       int
	hasLabelWindow        bool
}

// markerBlockRecord is the compiled state for marker_block patterns.
type markerBlockRecord struct {
	patternID     string
	beginMarker   string
	endMarker     string
	maxBlockBytes int
	severity      string
}

// Scanner holds the compiled pattern records. Safe for concurrent
// use: Scan mutates no internal state, and the compiled `*regexp.Regexp`
// values are themselves goroutine-safe.
type Scanner struct {
	regexRecords  []regexRecord
	markerRecords []markerBlockRecord
}

// libraryDoc mirrors the YAML schema. Optional fields use pointers so
// the compile pass can distinguish "absent" from "zero".
type libraryDoc struct {
	Patterns []libraryEntry `yaml:"patterns"`
}

type libraryEntry struct {
	ID                    string   `yaml:"id"`
	Strategy              string   `yaml:"strategy"`
	Regex                 string   `yaml:"regex"`
	Severity              string   `yaml:"severity"`
	EntropyMin            *float64 `yaml:"entropy_min"`
	MinLength             *int     `yaml:"min_length"`
	BeginMarker           string   `yaml:"begin_marker"`
	EndMarker             string   `yaml:"end_marker"`
	MaxBlockBytes         *int     `yaml:"max_block_bytes"`
	PairedWith            string   `yaml:"paired_with"`
	PairedMaxByteDistance *int     `yaml:"paired_max_byte_distance"`
	LabelRequired         []string `yaml:"label_required"`
	LabelByteWindow       *int     `yaml:"label_byte_window"`
}

// Default returns a scanner built from the embedded built_in.yaml.
// Compiled once per call; callers that need a per-process singleton
// should cache the returned scanner themselves. The embedded YAML is
// byte-identical to the Rust + Python copies.
func Default() (*Scanner, error) {
	return FromYAMLBytes(defaultYAML)
}

// FromYAMLBytes parses and compiles the supplied YAML pattern library.
// Authoring bugs (missing regex for a regex strategy, missing
// begin/end marker for a marker_block row, unknown paired_with
// reference) surface as errors at compile time so a typo lands here
// rather than as a silent scan miss in production.
func FromYAMLBytes(b []byte) (*Scanner, error) {
	var doc libraryDoc
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("credentialscanner: parse library: %w", err)
	}
	if doc.Patterns == nil {
		return nil, errors.New("credentialscanner: library must include a `patterns` list")
	}

	// First pass: id -> regex body so paired_with can resolve eagerly
	// (matches the Rust scanner's two-pass build).
	idToBody := make(map[string]string, len(doc.Patterns))
	for _, e := range doc.Patterns {
		if e.ID != "" && e.Regex != "" {
			idToBody[e.ID] = e.Regex
		}
	}

	s := &Scanner{}

	for _, e := range doc.Patterns {
		if e.ID == "" {
			// Entries without an id are silently dropped so a partial
			// YAML row never crashes the loader. Matches Python.
			continue
		}
		strategy := e.Strategy
		if strategy == "" {
			strategy = "regex"
		}
		severity := e.Severity
		if severity == "" {
			severity = "P2"
		}

		if strategy == "marker_block" {
			if e.BeginMarker == "" || e.EndMarker == "" {
				continue
			}
			cap := defaultMaxBlockBytes
			if e.MaxBlockBytes != nil {
				cap = *e.MaxBlockBytes
			}
			s.markerRecords = append(s.markerRecords, markerBlockRecord{
				patternID:     e.ID,
				beginMarker:   e.BeginMarker,
				endMarker:     e.EndMarker,
				maxBlockBytes: cap,
				severity:      severity,
			})
			continue
		}

		if e.Regex == "" {
			continue
		}
		compiled, err := regexp.Compile(e.Regex)
		if err != nil {
			return nil, fmt.Errorf("credentialscanner: pattern %q: bad regex: %w", e.ID, err)
		}

		rec := regexRecord{
			patternID: e.ID,
			regex:     compiled,
			severity:  severity,
		}

		switch strategy {
		case "regex_with_entropy":
			if e.EntropyMin != nil {
				rec.entropyMin = *e.EntropyMin
				rec.hasEntropyMin = true
			}
			if e.MinLength != nil {
				rec.minLength = *e.MinLength
				rec.hasMinLength = true
			}
		case "regex_with_paired_token":
			if e.PairedWith != "" {
				partnerBody, ok := idToBody[e.PairedWith]
				if !ok {
					return nil, fmt.Errorf("credentialscanner: pattern %q: %w %q",
						e.ID, ErrUnknownPairedPattern, e.PairedWith)
				}
				partner, err := regexp.Compile(partnerBody)
				if err != nil {
					return nil, fmt.Errorf("credentialscanner: pattern %q (partner of %q): bad regex: %w",
						e.PairedWith, e.ID, err)
				}
				rec.pairedRegex = partner
				rec.hasPairedRegex = true
			}
			if e.PairedMaxByteDistance != nil {
				rec.pairedMaxByteDistance = *e.PairedMaxByteDistance
			}
			if len(e.LabelRequired) > 0 {
				rec.labelRequired = append(rec.labelRequired, e.LabelRequired...)
			}
			if e.LabelByteWindow != nil {
				rec.labelByteWindow = *e.LabelByteWindow
				rec.hasLabelWindow = true
			}
			// Paired-token rows also honour the entropy + min_length
			// gates if the YAML sets them (e.g. AWS_SECRET_ACCESS_KEY).
			if e.EntropyMin != nil {
				rec.entropyMin = *e.EntropyMin
				rec.hasEntropyMin = true
			}
			if e.MinLength != nil {
				rec.minLength = *e.MinLength
				rec.hasMinLength = true
			}
		}

		s.regexRecords = append(s.regexRecords, rec)
	}

	return s, nil
}

// ShannonEntropy returns the Shannon entropy of `b` in bits per byte,
// computed over a 256-element byte histogram. Empty input returns 0.0.
//
// Exported so tests in this package and the credentialhook package can
// share the same helper without re-implementing the histogram math.
// Matches the Rust scanner's shannon_entropy helper bit-for-bit on
// ASCII inputs.
func ShannonEntropy(b []byte) float64 {
	if len(b) == 0 {
		return 0.0
	}
	var counts [256]int
	for _, c := range b {
		counts[c]++
	}
	total := float64(len(b))
	entropy := 0.0
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / total
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// Scan walks `text` against the compiled pattern library and returns
// every match. Pure: no I/O, no global state. Order mirrors the Rust
// scanner: regex-strategy patterns first (library order), then
// marker-block patterns (library order); within each pattern, byte
// order.
func (s *Scanner) Scan(text string) []Match {
	var out []Match

	for _, rec := range s.regexRecords {
		matches := rec.regex.FindAllStringSubmatchIndex(text, -1)
		for _, m := range matches {
			// Capture group 1 occupies indices [2..3]. Rows without a
			// group-1 capture, or matches where group 1 did not
			// participate (m[2] < 0), are skipped silently -- the
			// scanner treats them as authoring bugs rather than
			// raising.
			if len(m) < 4 || m[2] < 0 {
				continue
			}
			start, end := m[2], m[3]
			captured := text[start:end]

			if rec.hasMinLength && len(captured) < rec.minLength {
				continue
			}
			if rec.hasEntropyMin && ShannonEntropy([]byte(captured)) < rec.entropyMin {
				continue
			}
			if rec.hasPairedRegex || len(rec.labelRequired) > 0 {
				if !pairedConditionSatisfied(text, start, end, &rec) {
					continue
				}
			}

			out = append(out, Match{
				PatternID: rec.patternID,
				Severity:  rec.severity,
				Start:     start,
				End:       end,
			})
		}
	}

	for _, mb := range s.markerRecords {
		searchFrom := 0
		textLen := len(text)
		for searchFrom < textLen {
			idx := strings.Index(text[searchFrom:], mb.beginMarker)
			if idx < 0 {
				break
			}
			beginStart := searchFrom + idx
			probeEnd := beginStart + mb.maxBlockBytes
			if probeEnd > textLen {
				probeEnd = textLen
			}
			probeSlice := text[beginStart:probeEnd]

			// The end_marker must come AFTER the begin_marker; skip
			// the begin_marker bytes so a degenerate begin/end that
			// share a prefix cannot match the same bytes twice.
			earliest := len(mb.beginMarker)
			if earliest > len(probeSlice) {
				searchFrom = beginStart + len(mb.beginMarker)
				continue
			}

			rel := strings.Index(probeSlice[earliest:], mb.endMarker)
			if rel < 0 {
				searchFrom = beginStart + len(mb.beginMarker)
				continue
			}
			endMarkerStart := beginStart + earliest + rel
			endMarkerEnd := endMarkerStart + len(mb.endMarker)
			out = append(out, Match{
				PatternID: mb.patternID,
				Severity:  mb.severity,
				Start:     beginStart,
				End:       endMarkerEnd,
			})
			searchFrom = endMarkerEnd
		}
	}

	return out
}

// pairedConditionSatisfied mirrors the Rust scanner's
// paired_condition_satisfied. Either the partner regex co-occurs
// within paired_max_byte_distance OR a literal label appears within
// label_byte_window bytes of the candidate. Either is sufficient.
func pairedConditionSatisfied(text string, candidateStart, candidateEnd int, rec *regexRecord) bool {
	if rec.hasPairedRegex && rec.pairedMaxByteDistance > 0 {
		matches := rec.pairedRegex.FindAllStringSubmatchIndex(text, -1)
		maxDist := rec.pairedMaxByteDistance
		for _, m := range matches {
			if len(m) < 4 || m[2] < 0 {
				continue
			}
			partnerStart := m[2]
			diff := partnerStart - candidateStart
			if diff < 0 {
				diff = -diff
			}
			if diff <= maxDist {
				return true
			}
		}
	}

	if len(rec.labelRequired) > 0 && rec.hasLabelWindow {
		window := rec.labelByteWindow
		start := candidateStart - window
		if start < 0 {
			start = 0
		}
		end := candidateEnd + window
		if end > len(text) {
			end = len(text)
		}
		haystack := text[start:end]
		for _, label := range rec.labelRequired {
			if strings.Contains(haystack, label) {
				return true
			}
		}
	}

	return false
}

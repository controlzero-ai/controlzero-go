// Package controlzero exposes API key redaction + leak detection
// helpers shared by the host-side CLI and the runtime SDK. Mirrors
// the Python `controlzero.cli._secrets` module so all three SDKs
// agree on what counts as a leak.
//
// Tier 0a hotfix (#174). See docs/security/key-leak-postmortem.md.
package controlzero

import (
	"regexp"
	"strings"
)

// KeyMatch describes one occurrence of a `cz_(live|test)_*` substring
// inside arbitrary text.
type KeyMatch struct {
	Start      int
	End        int
	Key        string
	LineNumber int // 1-indexed
}

// keyPattern mirrors the Python `_KEY_PATTERN`. If it changes here,
// change it in `sdks/python/controlzero/controlzero/cli/_secrets.py`
// and `sdks/node/controlzero/src/cli/secrets.ts` so the cross-SDK
// CI contract test stays consistent.
var keyPattern = regexp.MustCompile(`cz_(?:live|test)_[A-Za-z0-9_]{4,}`)

// FindKeyLeaks returns every `cz_(live|test)_*` substring inside
// `text`. Safe on arbitrary untrusted input (linear regex).
func FindKeyLeaks(text string) []KeyMatch {
	if text == "" {
		return nil
	}
	idx := keyPattern.FindAllStringIndex(text, -1)
	out := make([]KeyMatch, 0, len(idx))
	for _, span := range idx {
		start, end := span[0], span[1]
		// 1-indexed line number: count newlines before the match.
		line := 1 + strings.Count(text[:start], "\n")
		out = append(out, KeyMatch{
			Start:      start,
			End:        end,
			Key:        text[start:end],
			LineNumber: line,
		})
	}
	return out
}

// RedactKey converts a full `cz_live_<64hex>` key to
// `cz_live_***<last5>`. Returns the input verbatim if it does not
// match the expected shape, so caller-side
// `fmt.Println(RedactKey(maybe))` is always safe.
func RedactKey(key string) string {
	stripped := strings.TrimSpace(key)
	if !keyPattern.MatchString(stripped) || keyPattern.FindString(stripped) != stripped {
		return key
	}
	// "live" or "test"
	mode := stripped[3:7]
	if len(stripped) < 5 {
		return key
	}
	return "cz_" + mode + "_***" + stripped[len(stripped)-5:]
}

// RedactText applies RedactKey to every `cz_(live|test)_*` match
// inside an arbitrary string.
func RedactText(text string) string {
	return keyPattern.ReplaceAllStringFunc(text, func(m string) string {
		return RedactKey(m)
	})
}

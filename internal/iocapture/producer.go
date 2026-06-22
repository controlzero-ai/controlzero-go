// Package iocapture is the agent-hook I/O capture PRODUCER (spine S4, T77 /
// epic #1390 / #1392).
//
// The producer turns a coding-agent hook payload into the captured
// input/output TEXT plus the honest provenance contract the I/O capture spine
// persists. It is the agent_hook io_source_type: a Claude Code (lead surface) /
// Cursor / Codex / Kiro / Gemini / Antigravity PreToolUse, PostToolUse,
// UserPromptSubmit, or Stop hook payload.
//
// Byte-for-byte parity contract with the Python producer
// (controlzero/_internal/io_capture_producer.py) and the Node producer
// (src/internal/ioCaptureProducer.ts): same field set, same completeness
// reading, same JSON rendering of structured values (compact, sorted keys).
//
// DETERMINISTIC + SIDE-EFFECT FREE. NO redaction, NO encryption -- those are S1
// (backend DLP) and S2 (backend per-record DEK). The producer only extracts +
// labels completeness honestly (#202 applied to a data row).
//
// CASCADE / GATE: a payload is attached only when the cascade is resolved ON
// (CaptureResolved, default via Options). The backend master gate
// (audit.IOCaptureWriteEnabled, NOT flipped by S4) is the persistence
// backstop -- a forwarded payload is dropped server-side until S7+S8.
package iocapture

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// Canonical io_source_type / io_capture_completeness strings. Mirror the
// backend audit.IOSourceType* / audit.IOCaptureCompleteness* enums so the
// producer never emits a value the ingest normalizer would fold to "failed".
const (
	IOSourceTypeAgentHook = "agent_hook"

	CompletenessFull              = "full"
	CompletenessPartialOutputOnly = "partial_output_only"
	CompletenessPartialInputOnly  = "partial_input_only"
	CompletenessNoneUnsupported   = "none_unsupported"
)

var inputEventNames = map[string]bool{
	"PreToolUse":       true,
	"preToolUse":       true,
	"UserPromptSubmit": true,
	"userPromptSubmit": true,
}

var outputEventNames = map[string]bool{
	"PostToolUse":   true,
	"postToolUse":   true,
	"Stop":          true,
	"stop":          true,
	"SubagentStop":  true,
	"subagentStop":  true,
}

// inputTextKeys are tool-input arg keys carrying the human-meaningful
// command/query/content, in extraction priority order. Mirrors the Python
// _INPUT_TEXT_KEYS / Node INPUT_TEXT_KEYS.
var inputTextKeys = []string{
	"command",
	"CommandLine",
	"sql",
	"query",
	"prompt",
	"content",
	"new_string",
	"text",
	"url",
}

var outputPayloadKeys = []string{
	"tool_response",
	"toolResponse",
	"tool_output",
	"toolOutput",
	"output",
	"response",
	"result",
}

var promptKeys = []string{"prompt", "user_prompt", "userPrompt", "promptText", "text"}

var stopResponseKeys = []string{"response", "message", "content", "text", "assistant_response"}

// Options configures a single extraction.
type Options struct {
	Surface         string
	ProducerVersion string
	InvocationID    string
	// CaptureResolved gates the producer: when false (the cascade vetoed this
	// call) an empty result is returned and no payload is attached. The zero
	// value is false, so callers MUST set it true to capture; the Extract entry
	// point exposes a CaptureResolved-defaulting helper for the common path.
	CaptureResolved bool
}

// coerceText renders an arbitrary hook value as faithful capture TEXT. A string
// is returned verbatim; a structured value is rendered as compact, sorted-key
// JSON for cross-SDK parity. Empty/nil -> "" so the caller treats it as absent.
func coerceText(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case bool:
		if v {
			return "true"
		}
		return "false"
	case map[string]any, []any:
		return stableJSON(v)
	default:
		return fmt.Sprintf("%v", v)
	}
}

// stableJSON renders a value as compact JSON with object keys sorted
// recursively, matching Python json.dumps(sort_keys=True, separators=(",",":"))
// and the Node stableStringify. Go's encoding/json already sorts map keys and
// emits compact output, so a plain Marshal matches.
func stableJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprintf("%v", v)
	}
	return string(b)
}

func asMap(v any) map[string]any {
	if m, ok := v.(map[string]any); ok {
		return m
	}
	return nil
}

func extractInputText(payload map[string]any, eventName string) string {
	if eventName == "UserPromptSubmit" || eventName == "userPromptSubmit" {
		for _, key := range promptKeys {
			if s, ok := payload[key].(string); ok && s != "" {
				return s
			}
		}
		return ""
	}

	toolInput := asMap(payload["tool_input"])
	if toolInput == nil {
		toolInput = asMap(payload["toolInput"])
	}
	if toolInput == nil {
		return ""
	}

	for _, key := range inputTextKeys {
		if text := coerceText(toolInput[key]); text != "" {
			return text
		}
	}
	if len(toolInput) > 0 {
		return coerceText(toolInput)
	}
	return ""
}

func extractOutputText(payload map[string]any, eventName string) string {
	if eventName == "Stop" || eventName == "stop" ||
		eventName == "SubagentStop" || eventName == "subagentStop" {
		for _, key := range stopResponseKeys {
			if text := coerceText(payload[key]); text != "" {
				return text
			}
		}
		return ""
	}

	for _, key := range outputPayloadKeys {
		if _, present := payload[key]; present {
			if text := coerceText(payload[key]); text != "" {
				return text
			}
		}
	}
	return ""
}

// ExtractAgentHookIO turns a coding-agent hook payload into the I/O capture
// contract fields. Returns a map whose keys are a SUBSET of the AuditIngestEntry
// I/O capture fields -- only the keys the producer can honestly populate --
// intended to be merged into the audit entry (the hook CLI passes it through
// GuardOptions.AuditExtras). When the cascade vetoes (opts.CaptureResolved
// false) or the payload structurally cannot carry I/O, an empty map is returned
// and NO payload is attached.
func ExtractAgentHookIO(payload map[string]any, opts Options) map[string]any {
	if !opts.CaptureResolved || payload == nil {
		return map[string]any{}
	}

	eventName, _ := payload["hook_event_name"].(string)
	if eventName == "" {
		eventName, _ = payload["hookEventName"].(string)
	}

	isInputEvent := inputEventNames[eventName]
	isOutputEvent := outputEventNames[eventName]
	if !isInputEvent && !isOutputEvent {
		if asMap(payload["tool_input"]) != nil || asMap(payload["toolInput"]) != nil {
			isInputEvent = true
		} else {
			return map[string]any{}
		}
	}

	var inputText, outputText string
	if isInputEvent {
		inputText = extractInputText(payload, eventName)
	}
	if isOutputEvent {
		outputText = extractOutputText(payload, eventName)
	}

	hasInput := inputText != ""
	hasOutput := outputText != ""
	if !hasInput && !hasOutput {
		return map[string]any{}
	}

	var completeness string
	switch {
	case hasInput && hasOutput:
		completeness = CompletenessFull
	case hasOutput:
		completeness = CompletenessPartialOutputOnly
	default:
		completeness = CompletenessPartialInputOnly
	}

	surface := opts.Surface
	if surface == "" {
		surface = "unknown"
	}

	result := map[string]any{
		"io_source_type":          IOSourceTypeAgentHook,
		"io_capture_surface":      surface,
		"io_producer_version":     opts.ProducerVersion,
		"io_capture_completeness": completeness,
		"io_input_captured":       hasInput,
		"io_output_captured":      hasOutput,
	}
	if opts.InvocationID != "" {
		result["io_invocation_id"] = opts.InvocationID
	}
	if hasInput {
		result["input_payload"] = inputText
	}
	if hasOutput {
		result["output_payload"] = outputText
	}
	return result
}

// SortedKeys is a small helper used by tests to assert a deterministic key set.
func SortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// stripPayloadKeys is the set of raw-cleartext keys callers strip from a LOCAL
// plaintext audit row. Exported as a doc anchor for the client.
var stripPayloadKeys = []string{"input_payload", "output_payload"}

// LocalStrippedPayloadKeys returns the raw payload keys that must be stripped
// before a row is written to a LOCAL plaintext audit log (they are encrypted
// server-side but the local log has no protection). Mirrors Python
// _LOCAL_STRIPPED_PAYLOAD_KEYS / Node's delete in auditDecision.
func LocalStrippedPayloadKeys() []string {
	out := make([]string, len(stripPayloadKeys))
	copy(out, stripPayloadKeys)
	return out
}

var _ = strings.TrimSpace // reserved for future surface-label normalization

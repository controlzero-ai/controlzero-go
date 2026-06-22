// Agent-hook I/O capture PRODUCER tests (spine S4, #1392).
//
// Mirrors the Python tests/test_io_capture_producer.py and the Node
// ioCaptureProducer.test.ts: a representative Claude Code hook payload (the
// lead surface) yields the captured input/output text plus an honest
// completeness contract; a no-op payload or a cascade veto yields nothing.
//
// fail-if-reverted: a PreToolUse payload must yield input_payload; a PostToolUse
// payload must yield output_payload; a cascade veto must yield an empty map.

package iocapture

import "testing"

func extract(payload map[string]any, opts Options) map[string]any {
	if opts.Surface == "" {
		opts.Surface = "claude_code"
	}
	if opts.ProducerVersion == "" {
		opts.ProducerVersion = "agent_hook@test"
	}
	return ExtractAgentHookIO(payload, opts)
}

func TestPreToolUse_ExtractsInput(t *testing.T) {
	out := extract(map[string]any{
		"session_id":      "sess-123",
		"transcript_path": "/tmp/t.jsonl",
		"cwd":             "/work",
		"tool_name":       "Bash",
		"tool_input":      map[string]any{"command": "ls -la /tmp"},
		"hook_event_name": "PreToolUse",
	}, Options{CaptureResolved: true, InvocationID: "sess-123"})

	if out["input_payload"] != "ls -la /tmp" {
		t.Errorf("input_payload = %v, want %q", out["input_payload"], "ls -la /tmp")
	}
	if _, present := out["output_payload"]; present {
		t.Errorf("output_payload should be absent: %v", out)
	}
	if out["io_source_type"] != IOSourceTypeAgentHook {
		t.Errorf("io_source_type = %v", out["io_source_type"])
	}
	if out["io_capture_surface"] != "claude_code" {
		t.Errorf("io_capture_surface = %v", out["io_capture_surface"])
	}
	if out["io_capture_completeness"] != CompletenessPartialInputOnly {
		t.Errorf("completeness = %v, want %q", out["io_capture_completeness"], CompletenessPartialInputOnly)
	}
	if out["io_input_captured"] != true || out["io_output_captured"] != false {
		t.Errorf("capture flags wrong: %v", out)
	}
	if out["io_invocation_id"] != "sess-123" {
		t.Errorf("io_invocation_id = %v", out["io_invocation_id"])
	}
}

func TestUserPromptSubmit_ExtractsPrompt(t *testing.T) {
	out := extract(map[string]any{
		"hook_event_name": "UserPromptSubmit",
		"prompt":          "Please refactor the auth module",
	}, Options{CaptureResolved: true})
	if out["input_payload"] != "Please refactor the auth module" {
		t.Errorf("input_payload = %v", out["input_payload"])
	}
	if out["io_capture_completeness"] != CompletenessPartialInputOnly {
		t.Errorf("completeness = %v", out["io_capture_completeness"])
	}
}

func TestPostToolUse_ExtractsOutput(t *testing.T) {
	out := extract(map[string]any{
		"tool_name":       "Bash",
		"tool_response":   "hi\n",
		"hook_event_name": "PostToolUse",
	}, Options{CaptureResolved: true})
	if out["output_payload"] != "hi\n" {
		t.Errorf("output_payload = %v", out["output_payload"])
	}
	if out["io_output_captured"] != true {
		t.Errorf("io_output_captured = %v", out["io_output_captured"])
	}
	if out["io_capture_completeness"] != CompletenessPartialOutputOnly {
		t.Errorf("completeness = %v", out["io_capture_completeness"])
	}
}

func TestPostToolUse_ObjectResponse_StableJSON(t *testing.T) {
	out := extract(map[string]any{
		"tool_name":       "Read",
		"tool_response":   map[string]any{"content": "file body", "lines": 3},
		"hook_event_name": "PostToolUse",
	}, Options{CaptureResolved: true})
	// Go encoding/json sorts map keys + emits compact output, matching the
	// Python json.dumps(sort_keys=True) / Node stableStringify contract.
	want := `{"content":"file body","lines":3}`
	if out["output_payload"] != want {
		t.Errorf("output_payload = %v, want %q", out["output_payload"], want)
	}
}

func TestStop_ExtractsResponse(t *testing.T) {
	out := extract(map[string]any{
		"hook_event_name": "Stop",
		"response":        "Done. Refactored auth.go.",
	}, Options{CaptureResolved: true})
	if out["output_payload"] != "Done. Refactored auth.go." {
		t.Errorf("output_payload = %v", out["output_payload"])
	}
}

func TestNotification_YieldsNothing(t *testing.T) {
	out := extract(map[string]any{"hook_event_name": "Notification", "message": "hi"},
		Options{CaptureResolved: true})
	if len(out) != 0 {
		t.Errorf("expected empty result, got %v", out)
	}
}

func TestEmptyToolInput_YieldsNothing(t *testing.T) {
	out := extract(map[string]any{
		"tool_name":       "Bash",
		"tool_input":      map[string]any{},
		"hook_event_name": "PreToolUse",
	}, Options{CaptureResolved: true})
	if len(out) != 0 {
		t.Errorf("expected empty result, got %v", out)
	}
}

func TestCaptureResolvedFalse_YieldsNothing(t *testing.T) {
	out := extract(map[string]any{
		"tool_name":       "Bash",
		"tool_input":      map[string]any{"command": "ls"},
		"hook_event_name": "PreToolUse",
	}, Options{CaptureResolved: false})
	if len(out) != 0 {
		t.Errorf("cascade veto must yield empty result, got %v", out)
	}
}

func TestEventlessPayloadWithToolInput_TreatedAsInput(t *testing.T) {
	out := extract(map[string]any{
		"tool_name":       "Bash",
		"tool_input":      map[string]any{"command": "whoami"},
		"session_id":      "s",
		"transcript_path": "/t",
	}, Options{CaptureResolved: true})
	if out["input_payload"] != "whoami" {
		t.Errorf("input_payload = %v", out["input_payload"])
	}
}

func TestAntigravityCamelCaseCommandLine(t *testing.T) {
	out := extract(map[string]any{
		"hook_event_name": "preToolUse",
		"tool_name":       "run_command",
		"tool_input":      map[string]any{"CommandLine": "rm -rf /tmp/x"},
	}, Options{CaptureResolved: true})
	if out["input_payload"] != "rm -rf /tmp/x" {
		t.Errorf("input_payload = %v", out["input_payload"])
	}
}

func TestLocalStrippedPayloadKeys(t *testing.T) {
	keys := LocalStrippedPayloadKeys()
	if len(keys) != 2 || keys[0] != "input_payload" || keys[1] != "output_payload" {
		t.Errorf("LocalStrippedPayloadKeys() = %v", keys)
	}
}

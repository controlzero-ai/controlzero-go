// Package examples contains compile-only smoke tests that mirror the
// code blocks in docs-site/docs/sdk/go.md. Their job is to catch docs
// drift: if the docs example calls a function that no longer exists,
// `go build ./examples/...` breaks here, and that breaks CI.
//
// Each function is named after the doc subsection it mirrors. Function
// bodies are compile-only (the actual call to cz.Guard runs against
// a tiny inline policy so we exercise the full path, not just types).
//
// Filed under issue #72.

package examples

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	controlzero "controlzero.ai/sdk/go"
)

// Mirrors "Local mode (no API key)" example from go.md.
func snippetLocalMode() {
	cz, err := controlzero.New(
		controlzero.WithPolicy(map[string]any{
			"rules": []any{
				map[string]any{"allow": "llm:generate", "reason": "test fixture"},
			},
		}),
	)
	if err != nil {
		log.Fatalf("controlzero: %v", err)
	}
	defer cz.Close()

	decision, err := cz.Guard("llm", controlzero.GuardOptions{
		Method: "generate",
		Args:   map[string]any{"model": "gpt-5.4"},
	})
	if err != nil {
		log.Fatalf("guard: %v", err)
	}
	if decision.Denied() {
		log.Printf("blocked by %s: %s", decision.PolicyID, decision.Reason)
		return
	}
}

// Mirrors "Inline policy map (no file)" example from go.md.
func snippetInlinePolicyMap() {
	_, _ = controlzero.New(
		controlzero.WithPolicy(map[string]any{
			"version": "1",
			"rules": []map[string]any{
				{"allow": "llm:generate", "reason": "LLM calls permitted"},
				{"deny": "filesystem:write_file", "reason": "no writes"},
			},
		}),
	)
}

// Mirrors "NewWithContext" example from go.md.
func snippetNewWithContext() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _ = controlzero.NewWithContext(ctx,
		// Use an inline policy here so the example does not need a real key
		// to compile-test against; in real code, swap to WithAPIKey.
		controlzero.WithPolicy(map[string]any{
			"rules": []any{map[string]any{"allow": "*", "reason": "fixture"}},
		}),
	)
}

// Mirrors "Hybrid mode" + "WithStrictHosted" examples from go.md.
func snippetHybridStrict() {
	_, err := controlzero.New(
		controlzero.WithPolicy(map[string]any{
			"rules": []any{map[string]any{"allow": "*", "reason": "fixture"}},
		}),
		controlzero.WithStrictHosted(),
	)
	_ = err
}

// Mirrors "Raise on deny" example from go.md.
func snippetRaiseOnDeny() {
	cz, _ := controlzero.New(
		controlzero.WithPolicy(map[string]any{
			"rules": []any{map[string]any{"deny": "filesystem:write_file", "reason": "no writes"}},
		}),
	)
	defer cz.Close()
	_, err := cz.Guard("filesystem", controlzero.GuardOptions{
		Method:      "write_file",
		Args:        map[string]any{"path": "/etc/passwd"},
		RaiseOnDeny: true,
	})
	var denied *controlzero.PolicyDeniedError
	if errors.As(err, &denied) {
		log.Printf("denied: %s", denied.Decision.Reason)
		return
	}
}

// Mirrors "With context" example from go.md.
func snippetEvalContext() {
	cz, _ := controlzero.New(
		controlzero.WithPolicy(map[string]any{
			"rules": []any{map[string]any{"allow": "*", "reason": "fixture"}},
		}),
	)
	defer cz.Close()
	_, _ = cz.Guard("database", controlzero.GuardOptions{
		Method: "query",
		Context: &controlzero.EvalContext{
			Resource: "table/orders",
			Tags: map[string]string{
				"agent_id":    "research-bot-1",
				"environment": "production",
			},
		},
	})
}

// Mirrors the "Typical matching" example from the Error handling section
// of go.md. Stays compile-only -- exercises the typed-error switch shape.
func snippetErrorMatching() {
	cz, err := controlzero.New(controlzero.WithPolicyFile("./controlzero.yaml"))
	if err != nil {
		var pve *controlzero.PolicyValidationError
		var ple *controlzero.PolicyLoadError
		switch {
		case errors.As(err, &pve):
			log.Fatalf("invalid policy in %s: %v", pve.Source, pve.Errors)
		case errors.As(err, &ple):
			log.Fatalf("could not load %s: %v", ple.Source, ple.Cause)
		default:
			log.Fatalf("controlzero: %v", err)
		}
	}
	if cz == nil {
		return
	}
	defer cz.Close()

	_, err = cz.Guard("tool", controlzero.GuardOptions{RaiseOnDeny: true})
	var denied *controlzero.PolicyDeniedError
	_ = errors.As(err, &denied)
}

// Mirrors the "Concurrency" example from go.md.
func snippetConcurrency() {
	cz, err := controlzero.New(
		controlzero.WithPolicy(map[string]any{
			"rules": []any{map[string]any{"allow": "*", "reason": "fixture"}},
		}),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer cz.Close()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(agentID string) {
			defer wg.Done()
			decision, _ := cz.Guard("llm", controlzero.GuardOptions{
				Method:  "generate",
				Context: &controlzero.EvalContext{Tags: map[string]string{"agent_id": agentID}},
			})
			_ = decision
		}(fmt.Sprintf("agent-%d", i))
	}
	wg.Wait()
}

// Compile-time references that document examples in the docs site mention
// but do not show executable code for. Keeping these symbols referenced
// here means renaming any of them in client.go breaks build with a clear
// blame trail.
var _ = []any{
	controlzero.WithAPIKey,
	controlzero.WithPolicyFile,
	controlzero.WithStrictHosted,
	controlzero.WithLogPath,
	controlzero.WithLogFormat,
	controlzero.WithLogRotation,
	os.Getenv, // doc references CONTROLZERO_API_KEY env var
}

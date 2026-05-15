// Package langchaingo wraps LangChainGo tools with Control Zero
// policy enforcement (issue #96).
//
// LangChainGo's tools.Tool interface is:
//
//	type Tool interface {
//	    Name() string
//	    Description() string
//	    Call(ctx context.Context, input string) (string, error)
//	}
//
// We implement that same interface and delegate to the inner tool
// after consulting the Control Zero policy engine. Denial returns a
// wrapped PolicyDeniedError; callers check with errors.As().
//
// Import dependency: this package imports tmc/langchaingo/tools.
// The root controlzero module does NOT depend on langchaingo -- only
// users who import this sub-package pay the cost.
//
// Usage:
//
//	import (
//	    controlzero "controlzero.ai/sdk/go"
//	    "controlzero.ai/sdk/go/integrations/langchaingo"
//	    "github.com/tmc/langchaingo/tools"
//	)
//
//	cz, _ := controlzero.New(controlzero.WithPolicyFile("./controlzero.yaml"))
//	governed := langchaingo.WrapTool(myTool, cz, langchaingo.Options{AgentID: "router"})
//	// pass `governed` to the LangChainGo agent instead of `myTool`.
package langchaingo

import (
	"context"

	controlzero "controlzero.ai/sdk/go"
	"github.com/tmc/langchaingo/tools"
)

// Options configure a wrapped tool. All fields are optional.
type Options struct {
	// AgentID is tagged on every guard + audit entry produced by this
	// wrapper.
	AgentID string
	// Tags are additional key-value labels appended to the audit
	// context for every call.
	Tags map[string]string
}

// governedTool implements the tools.Tool interface and delegates to
// an inner tool after the Control Zero policy check succeeds.
type governedTool struct {
	inner tools.Tool
	cz    *controlzero.Client
	opts  Options
}

// Name returns the underlying tool's name unchanged.
func (g *governedTool) Name() string { return g.inner.Name() }

// Description returns the underlying tool's description unchanged.
func (g *governedTool) Description() string { return g.inner.Description() }

// Call guards the invocation through Control Zero first. If the policy
// denies, the inner tool is NOT called and Call returns a wrapped
// *controlzero.PolicyDeniedError (match with errors.As). If the policy
// allows, Call delegates to the inner tool and returns its result.
func (g *governedTool) Call(ctx context.Context, input string) (string, error) {
	tags := map[string]string{
		"integration": "langchaingo",
		"agent_id":    g.opts.AgentID,
		"tool_name":   g.inner.Name(),
	}
	for k, v := range g.opts.Tags {
		tags[k] = v
	}

	decision, err := g.cz.Guard(g.inner.Name(), controlzero.GuardOptions{
		Method:      "call",
		Args:        map[string]any{"input": input},
		RaiseOnDeny: true,
		Context: &controlzero.EvalContext{
			Tags: tags,
		},
	})
	if err != nil {
		// RaiseOnDeny=true already wraps a denial as
		// *PolicyDeniedError. Anything else is genuine guard error.
		return "", err
	}
	_ = decision // allowed; nothing to do

	return g.inner.Call(ctx, input)
}

// WrapTool wraps a single LangChainGo tool with Control Zero
// governance. The returned value satisfies tools.Tool and can be
// passed anywhere LangChainGo expects a tool.
func WrapTool(t tools.Tool, cz *controlzero.Client, opts ...Options) tools.Tool {
	var o Options
	if len(opts) > 0 {
		o = opts[0]
	}
	return &governedTool{inner: t, cz: cz, opts: o}
}

// WrapTools is a convenience for wrapping a slice of tools in one
// call. Order is preserved.
func WrapTools(ts []tools.Tool, cz *controlzero.Client, opts ...Options) []tools.Tool {
	out := make([]tools.Tool, len(ts))
	for i, t := range ts {
		out[i] = WrapTool(t, cz, opts...)
	}
	return out
}

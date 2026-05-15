// Package templates exposes the policy templates as embedded files so the
// `controlzero` binary is self-contained.
package templates

import "embed"

//go:embed *.yaml
var FS embed.FS

// Names is the list of available template names. Add new templates here AND
// drop the YAML file in this directory.
var Names = []string{
	"generic",
	"rag",
	"mcp",
	"cost-cap",
	"claude-code",
	"langchain",
	"crewai",
	"cursor",
	"autogen",
}

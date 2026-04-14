# controlzero (Go)

AI agent governance for Go. Policies, audit, and observability for tool calls.
Works locally with no signup.

## Hello World

```go
package main

import (
    "fmt"
    "log"

    "controlzero.ai/sdk/go"
)

func main() {
    cz, err := controlzero.New(controlzero.WithPolicy(map[string]any{
        "rules": []any{
            map[string]any{"deny": "delete_*", "reason": "Hello World: deletes are blocked"},
            map[string]any{"allow": "*", "reason": "Hello World: everything else is fine"},
        },
    }))
    if err != nil {
        log.Fatal(err)
    }
    defer cz.Close()

    d, _ := cz.Guard("delete_file", controlzero.GuardOptions{
        Args: map[string]any{"path": "/tmp/foo"},
    })
    fmt.Println(d.Decision()) // "deny"

    d, _ = cz.Guard("read_file", controlzero.GuardOptions{
        Args: map[string]any{"path": "/tmp/foo"},
    })
    fmt.Println(d.Decision()) // "allow"
}
```

No API key. No signup. Run it.

## Install

```bash
go get controlzero.ai/sdk/go@v1.4.0
```

Pin to a specific version for reproducible builds. The version source of
truth is [`VERSION`](./VERSION); bumping that file triggers an
auto-tagged release on the public mirror repo (handled by the monorepo
sync workflow).

## Quickstart with the CLI

```bash
go install controlzero.ai/sdk/go/cmd/controlzero@latest

controlzero init
controlzero validate
controlzero test delete_file
```

The generated `controlzero.yaml` is the tutorial. It ships with annotated
rules covering allow lists, deny lists, wildcards, and the catch-all.

Templates available:

- `controlzero init` - Hello World template (default)
- `controlzero init -t rag` - RAG agent template (block exfiltration)
- `controlzero init -t mcp` - MCP server template
- `controlzero init -t cost-cap` - model allow-listing and cost guards

## Loading a policy

Three ways:

```go
// From a Go map
cz, _ := controlzero.New(controlzero.WithPolicy(map[string]any{
    "rules": []any{
        map[string]any{"deny": "delete_*"},
        map[string]any{"allow": "read_*"},
    },
}))

// From a YAML file
cz, _ := controlzero.New(controlzero.WithPolicyFile("./controlzero.yaml"))

// From an environment variable
// (set CONTROLZERO_POLICY_FILE=./controlzero.yaml)
cz, _ := controlzero.New()
```

If `./controlzero.yaml` exists in the current directory, it is picked up
automatically. No env var needed.

## Policy schema

```yaml
version: '1'
rules:
  - deny: 'delete_*'
    reason: 'Deletes need human approval'
  - allow: 'search'
  - allow: 'read_*'
  - allow: 'github:list_*'
  - deny: 'github:delete_repo'
  - deny: '*'
    reason: 'Default deny'
```

Rules are evaluated top to bottom. The first match wins. If no rule matches,
the call is denied (fail-closed).

## Local audit log

When running without an API key, every decision is written to `./controlzero.log`.
Configure rotation via options:

```go
cz, _ := controlzero.New(
    controlzero.WithPolicyFile("./controlzero.yaml"),
    controlzero.WithLogPath("./logs/controlzero.log"),
    controlzero.WithLogRotation(10, 5, 30, true), // 10MB, 5 backups, 30 days, gzip
    controlzero.WithLogFormat("json"),            // or "pretty"
)
```

When `CONTROLZERO_API_KEY` is set, audit ships to the remote dashboard and
log options are ignored with a warning.

## Hybrid mode

If you set both an API key AND pass a local policy, the local policy
**overrides** the dashboard policy and you get a loud WARN log on init.
For prod, use `WithStrictHosted()` to return an error instead:

```go
cz, err := controlzero.New(
    controlzero.WithAPIKey("cz_live_..."),
    controlzero.WithPolicy(localPolicy),
    controlzero.WithStrictHosted(),
)
// err is ErrHybridMode
```

## Hosted mode

Hosted mode ships dashboard-managed signed policy bundles and remote audit.
Pass your project API key; `New` hits `/v1/sdk/bootstrap`, pulls the signed
`.czpolicy` bundle, verifies the signature, decrypts locally, and enforces
every call against the dashboard policy. Audit streams to the remote trail.

```go
client, err := controlzero.New(controlzero.WithAPIKey("cz_live_..."))
if err != nil {
    log.Fatal(err)
}
defer client.Close()
```

Use `NewWithContext(ctx, ...)` to pass your own context. Bootstrap keys
and the bundle are cached under `~/.controlzero/cache/` so restarts work
offline.

## Framework examples

Full integration guides at [docs.controlzero.ai/sdk/integrations](https://docs.controlzero.ai/sdk/integrations).

## License

Apache 2.0

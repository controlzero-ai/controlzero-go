// Hello World: no API key, no signup.
//
// Run:
//
//	go run examples/hello_world.go
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

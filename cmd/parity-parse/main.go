// Parse the parity fixture with the Go SDK bundle parser and print
// canonical JSON of the translated policy.
//
// Usage: go run parse_go.go <fixture_dir>
package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"controlzero.ai/sdk/go/internal/bundle"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: parse_go <fixture_dir>")
		os.Exit(1)
	}
	d := os.Args[1]
	blob, err := os.ReadFile(filepath.Join(d, "bundle.bin"))
	if err != nil {
		panic(err)
	}
	encB64, _ := os.ReadFile(filepath.Join(d, "enc_key.b64"))
	pubHex, _ := os.ReadFile(filepath.Join(d, "pub_key.hex"))

	enc, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(encB64)))
	if err != nil {
		panic(err)
	}
	pub, err := hex.DecodeString(strings.TrimSpace(string(pubHex)))
	if err != nil {
		panic(err)
	}

	parsed, err := bundle.Parse(blob, enc, pub, nil)
	if err != nil {
		panic(err)
	}

	local := bundle.TranslateToLocalPolicy(parsed.Payload)
	out, _ := json.MarshalIndent(local, "", "  ")
	fmt.Println(string(out))
}

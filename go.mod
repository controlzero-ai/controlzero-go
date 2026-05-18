module controlzero.ai/sdk/go

go 1.24.4

toolchain go1.24.13

require (
	github.com/gowebpki/jcs v1.0.1
	github.com/klauspost/compress v1.18.0
	github.com/spf13/cobra v1.8.0
	github.com/tmc/langchaingo v0.1.14
	gopkg.in/natefinch/lumberjack.v2 v2.2.1
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/dlclark/regexp2 v1.10.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/pkoukk/tiktoken-go v0.1.6 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	go.starlark.net v0.0.0-20230302034142-4b1e35fe2254 // indirect
	golang.org/x/sys v0.35.0 // indirect
)

// Retracted range [v1.7.0, v1.7.4]:
//   v1.7.0, v1.7.1, v1.7.2 -- contained customer-name references in
//     inline comments and a realistic-looking cz_live_* test fixture
//     (privacy class). Source verified via:
//       git show sdks/go/controlzero/v1.7.X:sdks/go/controlzero/client.go
//   v1.7.3 -- scrubbed source but its tag was deleted from the mirror
//     at controlzero-ai/controlzero-go during the 2026-05-16 history
//     rewrite, so the tag no longer resolves at the upstream.
//     proxy.golang.org cache is independent and is being addressed
//     by a separate module-proxy-removal request.
//   v1.7.4 -- shipped the un-scrubbed api_key_mask_test.go fixture
//     (a 64-hex string whose format mimicked a customer secret too
//     closely). v1.7.5 is the clean version. Same privacy-class
//     concern as v1.7.0..v1.7.2.
// Use v1.7.5 or later.
retract [v1.7.0, v1.7.4]

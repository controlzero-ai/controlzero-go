// Code generated from sdks/error-catalog/error_codes.yaml by scripts/codegen/gen_error_catalog.py; DO NOT EDIT.
//
// Shared error-code catalog for the controlzero SDK. A given E#### code
// carries the same title + fix hint + doc URL across the Python, Node, and
// Go SDKs (issue #893). To change a code, edit the manifest and re-run the
// generator -- never hand-edit this file.

package controlzero

import "fmt"

// ErrorCodeRecord is a single entry in the shared error-code catalog.
type ErrorCodeRecord struct {
	// Code is the E#### stable identifier.
	Code string
	// Title is a one-line summary suitable for an error-message header.
	Title string
	// What explains what happened, in user terms (2-3 sentences).
	What string
	// Fix is an actionable next step the user can run.
	Fix string
	// Doc is the slug under docs.controlzero.ai/errors/.
	Doc string
}

// errorCatalog holds the full catalog, keyed by E#### code. Unexported so
// callers go through GetErrorCode / AllErrorCodes and cannot mutate it.
var errorCatalog = map[string]ErrorCodeRecord{
	`E1001`: {
		Code:  `E1001`,
		Title: `API key found in agent settings file`,
		What:  `An agent settings file (e.g. ~/.claude/settings.json) contains a plaintext cz_live_* or cz_test_* key inside a hook command. On every tool invocation the key is echoed to the agent's stderr, where it can be captured by terminal scrollback, shell history, or log files.`,
		Fix:   "Run `controlzero migrate` to move the key into ~/.controlzero/config.yaml (mode 0600) and rewrite the hook to read $CONTROLZERO_API_KEY from the env. Then rotate the leaked key in the dashboard.",
		Doc:   `E1001-api-key-in-settings`,
	},
	`E1002`: {
		Code:  `E1002`,
		Title: `~/.controlzero directory is world-readable`,
		What:  `The directory holding your API key has permissions other than 0700. Other local users on this machine can read its contents.`,
		Fix:   "Run `chmod 700 ~/.controlzero`.",
		Doc:   `E1002-config-dir-perms`,
	},
	`E1003`: {
		Code:  `E1003`,
		Title: `config.yaml is world-readable`,
		What:  `The API key on disk has file permissions other than 0600. Other local users on this machine can read the key.`,
		Fix:   "Run `chmod 600 ~/.controlzero/config.yaml` or re-run `controlzero install` to re-apply.",
		Doc:   `E1003-config-file-perms`,
	},
	`E1004`: {
		Code:  `E1004`,
		Title: `API key found in shell history`,
		What:  `An API key was found in your shell history file (.bash_history / .zsh_history). Histories are typically synced to cloud backups and are readable to any process running as the same user.`,
		Fix:   "Rotate the key in the dashboard, then scrub the history entry with `history -d <number>` or by editing the history file directly.",
		Doc:   `E1004-key-in-shell-history`,
	},
	`E1005`: {
		Code:  `E1005`,
		Title: `Cannot read an agent settings file`,
		What:  `Doctor wanted to scan an agent settings file but the file is unreadable (permissions / disk error). We can't confirm whether the file contains a leaked key.`,
		Fix:   `Check the file's permissions. If it should be readable to you, fix the perms; if it shouldn't exist at all, delete it.`,
		Doc:   `E1005-unreadable-settings`,
	},
	`E1101`: {
		Code:  `E1101`,
		Title: `API key rejected (401)`,
		What:  `The hosted backend rejected the API key with HTTP 401. The key is unknown, revoked, expired, or a never-activated placeholder. For safety the backend does not say which (so a 401 cannot be used to probe which keys exist), but in every case the same fix applies: the key you are using is no longer valid.`,
		Fix:   `Generate a fresh key in the dashboard under Settings -> API Keys (https://app.controlzero.ai/settings/api-keys) and set CONTROLZERO_API_KEY to it. If you just rotated a key, make sure the environment your agent runs in picked up the new value.`,
		Doc:   `E1101-key-rejected`,
	},
	`E1102`: {
		Code:  `E1102`,
		Title: `Enrollment token expired`,
		What:  `The single-use enrollment token from the dashboard has expired or was already consumed. Each token is valid for 15 minutes and one enrollment.`,
		Fix:   "Generate a fresh token in the dashboard and re-run `controlzero enroll --token=...`.",
		Doc:   `E1102-enroll-token-expired`,
	},
	`E1103`: {
		Code:  `E1103`,
		Title: `No API key found`,
		What:  `The SDK looked for an API key in $CONTROLZERO_API_KEY and ~/.controlzero/config.yaml but neither produced one.`,
		Fix:   "Either export `CONTROLZERO_API_KEY=cz_live_...` in your shell, or run `controlzero install <agent> --api-key=cz_live_...` to write it to the config file.",
		Doc:   `E1103-no-api-key`,
	},
	`E1104`: {
		Code:  `E1104`,
		Title: `API key format invalid`,
		What:  "The string supplied as the API key does not match the expected shape (`cz_live_*` or `cz_test_*` followed by 64 hex characters).",
		Fix:   `Copy the key from the dashboard directly; do not URL-encode or wrap it in quotes when exporting.`,
		Doc:   `E1104-key-format-invalid`,
	},
	`E1201`: {
		Code:  `E1201`,
		Title: `Policy file failed validation`,
		What:  `The local policy file (controlzero.yaml or controlzero.json) does not conform to the policy schema. See the error list immediately above for which fields are wrong.`,
		Fix:   "Run `controlzero validate <file>` to get the same errors formatted as a checklist. Or open the file in your editor and fix the fields.",
		Doc:   `E1201-policy-validate`,
	},
	`E1202`: {
		Code:  `E1202`,
		Title: `Policy file not found`,
		What:  `The SDK was told to load a policy from a path that does not exist.`,
		Fix:   `Double-check the path you passed to policy_file=. If you meant to use the global policy, drop the argument and let the SDK find ~/.controlzero/policy.yaml automatically.`,
		Doc:   `E1202-policy-not-found`,
	},
	`E1203`: {
		Code:  `E1203`,
		Title: `Policy bundle signature mismatch`,
		What:  `The signed policy bundle the SDK pulled from the backend has a signature that does not match the expected public key. This is a tamper signal: someone may have modified the bundle in transit or on disk.`,
		Fix:   `Delete the cached bundle (~/.controlzero/bundle-cz_*.bin), restart the SDK, and re-pull. If the error recurs, escalate to support.`,
		Doc:   `E1203-bundle-sig`,
	},
	`E1204`: {
		Code:  `E1204`,
		Title: `Policy version conflict`,
		What:  `The local policy and the hosted policy disagree on which version is current. SDK precedence (T103) means the hosted version wins, but we surface a warning so you know about it.`,
		Fix:   "Pick one source of truth. If you want the hosted policy: delete the local file. If you want the local policy: run `controlzero install <agent> --local-override` to opt out of hosted.",
		Doc:   `E1204-version-conflict`,
	},
	`E1205`: {
		Code:  `E1205`,
		Title: `Policy bundle missing -- fail-closed engaged`,
		What:  `Hosted mode is configured but no cached bundle is available and the backend is unreachable. The SDK refuses to construct rather than silently allow every tool call.`,
		Fix:   "Check network reachability to api.controlzero.ai. If you're offline by design, pre-cache the bundle with `controlzero policy-pull` while you have connectivity.",
		Doc:   `E1205-fail-closed`,
	},
	`E1301`: {
		Code:  `E1301`,
		Title: `Cache directory permissions wrong`,
		What:  `~/.controlzero needs mode 0700. Found a different mode.`,
		Fix:   "Run `chmod 700 ~/.controlzero`.",
		Doc:   `E1301-cache-perms`,
	},
	`E1302`: {
		Code:  `E1302`,
		Title: `Stale bundle for rotated key`,
		What:  `T104 cache GC found a cached bundle whose key prefix no longer matches any active key in your enrollment. Almost always means a key rotated and the old bundle should be discarded.`,
		Fix:   "Run `controlzero policy-pull` to refresh, or delete the stale bundle: `rm ~/.controlzero/bundle-cz_*.bin`.",
		Doc:   `E1302-stale-bundle`,
	},
	`E1303`: {
		Code:  `E1303`,
		Title: `Audit log not writable`,
		What:  `The SDK can't append to ~/.controlzero/audit.log. Usually a permissions or out-of-disk issue.`,
		Fix:   "Check `ls -la ~/.controlzero/audit.log` and `df -h ~`. If perms are wrong, `chmod 600 ~/.controlzero/audit.log`.",
		Doc:   `E1303-audit-write`,
	},
	`E1401`: {
		Code:  `E1401`,
		Title: `Backend unreachable`,
		What:  `The SDK could not connect to api.controlzero.ai (or whatever CONTROLZERO_API_URL points at). Tool calls will use the cached policy bundle; new audit events buffer locally.`,
		Fix:   "Check `curl -I https://api.controlzero.ai`. If you're behind a corporate proxy, set HTTPS_PROXY before launching your agent.",
		Doc:   `E1401-backend-unreachable`,
	},
	`E1402`: {
		Code:  `E1402`,
		Title: `Backend returned 5xx`,
		What:  `The backend returned a server error. Transient. The SDK will retry on the next guard() call. Audit events buffer locally and flush when the backend recovers.`,
		Fix:   `If it persists for more than a few minutes, check status.controlzero.ai or open a support ticket with the timestamp.`,
		Doc:   `E1402-backend-5xx`,
	},
	`E1403`: {
		Code:  `E1403`,
		Title: `Rate limit exceeded`,
		What:  `The hosted backend rate-limited this client (HTTP 429 with a Retry-After header). The SDK does not retry automatically, and hook enforcement fails closed: the guarded tool call is denied rather than allowed through ungoverned.`,
		Fix:   `Wait for the Retry-After window (60s by default) and retry. If you see this consistently, your usage may have crossed your tier's limit. Check the dashboard's Usage page.`,
		Doc:   `E1403-rate-limit`,
	},
	`E1404`: {
		Code:  `E1404`,
		Title: `TLS verification failed`,
		What:  `The TLS handshake to api.controlzero.ai failed verification. Usually a corporate MITM proxy that injects its own CA, or a system clock that's badly out of sync.`,
		Fix:   `Either point the SDK at your corporate CA bundle (REQUESTS_CA_BUNDLE=/path/to/corp.pem) or fix the system clock.`,
		Doc:   `E1404-tls-verify`,
	},
	`E1405`: {
		Code:  `E1405`,
		Title: `Feature not available on your plan`,
		What:  `The backend rejected the request with HTTP 403 and code FEATURE_NOT_AVAILABLE: the feature this endpoint serves (for example coding hooks or the Scout agent, both Teams-tier) is not included in your organization's current plan. This is a billing gate, not an authentication failure -- the API key or machine signature was accepted.`,
		Fix:   `Upgrade the organization's plan in the dashboard (Settings > Billing, or the upgrade_url field in the error body). The response's feature and tier fields name the gated feature and your current plan.`,
		Doc:   `E1405-feature-not-on-plan`,
	},
	`E1500`: {
		Code:  `E1500`,
		Title: `Approvals disabled at this scope`,
		What:  `POST /api/approval-requests was rejected with HTTP 412 because the hitl_settings cascade resolved to enabled=false at the scope reported in the response body (api_key, project, org, or default). The default is fail-closed: an unconfigured org cannot silently accept approval traffic. Toggling the setting in the dashboard at the correct scope is the only way to re-enable the flow.`,
		Fix:   `Open the Approvals settings page in the dashboard, find the row at the resolved_scope reported by the error, and flip the Enabled toggle on. If resolved_scope=default, create the row at the scope you want to govern.`,
		Doc:   `E1500-approvals-disabled`,
	},
	`E1501`: {
		Code:  `E1501`,
		Title: `Hook input was not JSON`,
		What:  `The agent invoked the controlzero hook subprocess but the stdin payload could not be parsed as JSON. The hook fails open (allows the tool call) so the agent does not stall.`,
		Fix:   "Re-install the hook with `controlzero install <agent>` to fix any manual edits to the agent's settings file that may have corrupted the contract.",
		Doc:   `E1501-hook-bad-json`,
	},
	`E1502`: {
		Code:  `E1502`,
		Title: `Hook timed out`,
		What:  `The hook subprocess took longer than 5 seconds to return a decision. The agent allowed the tool call to proceed rather than blocking on us.`,
		Fix:   "Usually a slow disk or a hung network call. Run `controlzero doctor -v` to confirm the cache files are readable.",
		Doc:   `E1502-hook-timeout`,
	},
	`E1503`: {
		Code:  `E1503`,
		Title: `Hook returned the wrong decision key`,
		What:  `Claude Code's hook spec accepts decision: 'approve' or 'block'. An older controlzero version emitted decision: 'allow', which Claude silently discarded -- bypassing the policy entirely. The 1.5.3 host-agent adapter base fixed this.`,
		Fix:   `Upgrade to controlzero >= 1.5.3.`,
		Doc:   `E1503-decision-key`,
	},
	`E1504`: {
		Code:  `E1504`,
		Title: `Windows agent hook syntax error`,
		What:  "The agent's settings file uses `VAR=value command` bash-prefix syntax for the hook command. PowerShell and cmd.exe cannot parse this -- the hook silently fails on every Windows agent.",
		Fix:   "Re-install with `controlzero install <agent>`. The current install path emits the portable form.",
		Doc:   `E1504-windows-hook`,
	},
	`E1601`: {
		Code:  `E1601`,
		Title: `guard() called after close()`,
		What:  `Your code called Client.guard() on a Client that already had close() called on it. The SDK refuses to continue auditing because the audit sinks have been drained and shut down.`,
		Fix:   `Restructure your code so close() runs exactly once, at the end of the agent's lifecycle. The most common cause is putting close() inside a finally that fires per-iteration instead of once.`,
		Doc:   `E1601-guard-after-close`,
	},
	`E1602`: {
		Code:  `E1602`,
		Title: `Tool name not in canonical vocab`,
		What:  "The tool action you passed to guard() does not match any rule in your policy AND does not match any canonical alias. The action was logged as `unknown_tool` and the synthetic NO_RULE_MATCH decision applied.",
		Fix:   "Either add a rule covering this action, or `controlzero validate` your policy with --suggest to see did-you-mean hints from T86.",
		Doc:   `E1602-unknown-tool`,
	},
	`E1603`: {
		Code:  `E1603`,
		Title: `Args hash mismatch (deterministic check)`,
		What:  `The args hash recomputed by the engine on this audit row does not match the args hash the SDK shipped. Either the args were mutated in flight or the JCS canonicalizer drifted between SDK + engine.`,
		Fix:   "Upgrade the SDK to match the engine version (run `controlzero version` and compare against the backend health endpoint).",
		Doc:   `E1603-args-hash-drift`,
	},
	`E1701`: {
		Code:  `E1701`,
		Title: `Approval request timed out`,
		What:  `The approver did not decide before timeout_s elapsed. The SDK raises HITLTimeoutError (a PolicyDeniedError) so the agent code path can treat 'no decision' identically to an explicit deny.`,
		Fix:   `Increase timeout_s on the request_approval() call, or escalate to an approver via /api/approval-requests/{id}/delegate.`,
		Doc:   `E1701-hitl-timeout`,
	},
	`E1702`: {
		Code:  `E1702`,
		Title: `Approval backend unreachable`,
		What:  `POST /api/approval-requests failed after retries. The SDK could not queue the request and fails closed (PolicyDeniedError) rather than silently letting the action through.`,
		Fix:   `Confirm CONTROLZERO_API_URL reaches the backend, then retry. Check the gateway health endpoint and the controlzero-backend logs for ingest errors.`,
		Doc:   `E1702-hitl-backend-unreachable`,
	},
	`E1703`: {
		Code:  `E1703`,
		Title: `Approval policy version conflict`,
		What:  `The policy bundle the SDK is enforcing does not include the rule that produced this approval request, so the SDK refuses to wait on it. Common after a hot bundle swap mid-flight.`,
		Fix:   "Re-pull the bundle (`controlzero install --api-key ...`) or restart the agent to pick up the new bundle, then retry.",
		Doc:   `E1703-hitl-policy-version-conflict`,
	},
	`E1704`: {
		Code:  `E1704`,
		Title: `Approvals not configured for this org`,
		What:  `request_approval() requires the org to have approval settings configured (PUT /api/orgs/{orgID}/hitl-settings). The SDK raised HITLNotConfiguredError because the backend returned the default shape with is_configured: false.`,
		Fix:   `Configure Approvals in the dashboard Settings > Approvals tab, or PUT the settings document directly.`,
		Doc:   `E1704-hitl-not-configured`,
	},
	`E1705`: {
		Code:  `E1705`,
		Title: `No approver available`,
		What:  `The org has approvals configured but the approver pool is empty (no active members with the approver role at the configured scope). The SDK fails closed: no approver, no approval.`,
		Fix:   `Invite at least one approver to the org and re-run, or change the scope binding in the approval settings.`,
		Doc:   `E1705-hitl-no-approver`,
	},
	`E1706`: {
		Code:  `E1706`,
		Title: `Requestor identity not in org`,
		What:  `The X-CZ-Requestor-Email header resolved to a user that is not a member of the org owning the API key. The SDK rejects the request rather than letting a stale email claim a guarded action.`,
		Fix:   "Run `controlzero install <agent> --email <addr>` with an email that matches an active org member.",
		Doc:   `E1706-hitl-identity-not-in-org`,
	},
	`E1707`: {
		Code:  `E1707`,
		Title: `Requestor identity required`,
		What:  `request_approval() was called without an X-CZ-Requestor-Email header (or the header was empty). Approvals need a human to attribute the request to; anonymous approvals are not allowed.`,
		Fix:   "Run `controlzero install <agent> --email <addr>` to persist the operator email under ~/.controlzero/config.yaml.",
		Doc:   `E1707-hitl-identity-required`,
	},
	`E1708`: {
		Code:  `E1708`,
		Title: `Requestor identity claim rejected`,
		What:  `The backend resolver rejected the X-CZ-Requestor-Email claim (unknown user, deactivated user, or org mismatch). The SDK surfaces this as a PolicyDeniedError so the action is blocked.`,
		Fix:   `Confirm the email is correct, the user is active in the org, and their membership has not been revoked.`,
		Doc:   `E1708-hitl-identity-claim-rejected`,
	},
	`E1709`: {
		Code:  `E1709`,
		Title: `Secret value leak in payload`,
		What:  `A wire payload field (request body, audit row, structured log, exception message) matched the secret-value-shape regex. The SDK aborts before sending rather than ship plaintext secrets to the backend.`,
		Fix:   `Inspect the call site for unredacted secret strings. Use get_secret() to fetch values instead of embedding them in args.`,
		Doc:   `E1709-secret-leak-in-payload`,
	},
	`E1710`: {
		Code:  `E1710`,
		Title: `Secret approval required`,
		What:  `get_secret() resolved a policy that requires approval for this secret name. The SDK queued an approval request; the caller should await the returned PendingApproval or treat the denied decision as a hard stop.`,
		Fix:   `Approve via the dashboard Approvals tab, or call PendingApproval.wait() to block until the decision lands.`,
		Doc:   `E1710-secret-approval-required`,
	},
	`E1711`: {
		Code:  `E1711`,
		Title: `Secret not found`,
		What:  `get_secret(name) did not find a secret with that name. The SDK raises SecretNotFound rather than returning None so missing secrets fail loudly at the call site.`,
		Fix:   `Confirm the secret exists in the dashboard Secrets tab and the name matches exactly (case-sensitive).`,
		Doc:   `E1711-secret-not-found`,
	},
	`E1712`: {
		Code:  `E1712`,
		Title: `Bundle requires a newer SDK`,
		What:  `The hosted policy bundle declares min_sdk_version higher than this SDK. The bundle uses rule selectors (clients / projects) this SDK does not understand. Loading it as-is would treat the selectors as wildcards -- a silent over-block where a deny scoped to one agent would apply to ALL agents.`,
		Fix:   "Upgrade controlzero on every agent in the fleet (`pip install -U controlzero` / `npm install -g @controlzero/sdk@latest` / `go get controlzero@latest`) to at least the version the bundle declares.",
		Doc:   `E1712-bundle-requires-newer-sdk`,
	},
	`E2001`: {
		Code:  `E2001`,
		Title: `Credential leak detected in tool output`,
		What:  "The credential leak handler scanned an agent tool output (stdout, stderr, file-read body, or grep match) and found one or more high-confidence credential matches. The configured action was `block`, so the SDK raised CredentialLeakBlocked rather than letting the credential reach the agent's prompt or downstream log.",
		Fix:   "Rotate the leaked credential immediately, then either allowlist the pattern_id for this org (if the match is a known false positive) or set the per-org override to `redact` so future matches mask the value in-place rather than aborting the call.",
		Doc:   `E2001-credential-leak-blocked`,
	},
}

// errorCatalogOrder preserves the manifest order so AllErrorCodes is
// deterministic across runs (Go map iteration order is randomized).
var errorCatalogOrder = []string{
	`E1001`,
	`E1002`,
	`E1003`,
	`E1004`,
	`E1005`,
	`E1101`,
	`E1102`,
	`E1103`,
	`E1104`,
	`E1201`,
	`E1202`,
	`E1203`,
	`E1204`,
	`E1205`,
	`E1301`,
	`E1302`,
	`E1303`,
	`E1401`,
	`E1402`,
	`E1403`,
	`E1404`,
	`E1405`,
	`E1500`,
	`E1501`,
	`E1502`,
	`E1503`,
	`E1504`,
	`E1601`,
	`E1602`,
	`E1603`,
	`E1701`,
	`E1702`,
	`E1703`,
	`E1704`,
	`E1705`,
	`E1706`,
	`E1707`,
	`E1708`,
	`E1709`,
	`E1710`,
	`E1711`,
	`E1712`,
	`E2001`,
}

// GetErrorCode looks up an error code. The second return is false when the
// code is not in the catalog; callers that prefer a panic-on-miss can wrap
// it. Shipping an unknown E#### to a user is a bug, so most call sites
// should treat a miss as a programming error.
func GetErrorCode(code string) (ErrorCodeRecord, bool) {
	rec, ok := errorCatalog[code]
	return rec, ok
}

// AllErrorCodes returns every catalog code in manifest order.
func AllErrorCodes() []string {
	out := make([]string, len(errorCatalogOrder))
	copy(out, errorCatalogOrder)
	return out
}

// ErrorDocURL returns the full docs URL for a code's doc slug. Empty string
// when the code is unknown.
func ErrorDocURL(code string) string {
	rec, ok := errorCatalog[code]
	if !ok {
		return ""
	}
	return fmt.Sprintf("https://docs.controlzero.ai/errors/%s", rec.Doc)
}

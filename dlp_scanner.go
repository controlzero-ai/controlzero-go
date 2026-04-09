package controlzero

// DLP (Data Loss Prevention) scanner for tool argument inspection.
//
// Scans text content from tool arguments for PII, secrets, and sensitive data
// patterns. Used by the policy evaluator to block or flag tool calls whose
// arguments contain sensitive content, even when the tool itself is allowed by
// policy rules.
//
// Two pattern sources:
//   1. Built-in patterns: high-confidence regexes shipped with the SDK.
//      Always active, zero config. Work in local-only mode.
//   2. Custom rules: loaded from the policy file's dlp_rules section
//      or pulled from backend for enrolled SDKs.
//
// Secret-category matches store a SHA-256 hash of the matched text, never the
// plaintext. This is consistent with the browser extension's HMAC approach.
//
// Pattern categories:
//   pii        - Personally identifiable information (SSN, RRN, etc.)
//   financial  - Financial data (credit cards, IBAN, etc.)
//   healthcare - HIPAA-relevant identifiers (NPI, DEA, etc.)
//   secret     - API keys, tokens, credentials, connection strings

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
)

// ---------------------------------------------------------------------------
// DLP rule and match types
// ---------------------------------------------------------------------------

// DLPRule is a single DLP scanning rule with a precompiled regex.
type DLPRule struct {
	ID       string
	Name     string
	Pattern  string
	Category string // "pii", "financial", "secret", "healthcare"
	Action   string // "detect", "block", "mask"
	Region   string
	compiled *regexp.Regexp
}

// DLPMatch is a single DLP match result.
type DLPMatch struct {
	RuleID      string
	RuleName    string
	Category    string
	Action      string
	MatchedText string // plaintext for pii/financial, SHA-256 hash for secret
	Offset      int
	Count       int
}

// ---------------------------------------------------------------------------
// Built-in pattern definitions, compiled at package init time.
// All builtins use action="detect". Admins add action="block" via custom rules.
// ---------------------------------------------------------------------------

type patternDef struct {
	id       string
	name     string
	pattern  string
	category string
	region   string
}

// PII: United States
var piiUS = []patternDef{
	{
		id:       "builtin-us-ssn",
		name:     "US SSN",
		pattern:  `\b\d{3}-\d{2}-\d{4}\b`,
		category: "pii",
		region:   "us",
	},
	{
		id:       "builtin-us-phone",
		name:     "US Phone",
		pattern:  `\b(?:\+1[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b`,
		category: "pii",
		region:   "us",
	},
}

// PII: Korea
var piiKR = []patternDef{
	{
		id:       "builtin-kr-rrn",
		name:     "Korean RRN",
		pattern:  `\b\d{6}-[1-4]\d{6}\b`,
		category: "pii",
		region:   "kr",
	},
	{
		id:       "builtin-kr-phone",
		name:     "Korean Phone",
		pattern:  `\b01[016789]-\d{3,4}-\d{4}\b`,
		category: "pii",
		region:   "kr",
	},
	{
		id:       "builtin-kr-brn",
		name:     "Korean BRN",
		pattern:  `\b\d{3}-\d{2}-\d{5}\b`,
		category: "pii",
		region:   "kr",
	},
	{
		id:       "builtin-kr-drivers-license",
		name:     "Korean Driver License",
		pattern:  `\b\d{2}-\d{2}-\d{6}-\d{2}\b`,
		category: "pii",
		region:   "kr",
	},
	{
		id:       "builtin-kr-passport",
		name:     "Korean Passport",
		pattern:  `\b[MS]\d{8}\b`,
		category: "pii",
		region:   "kr",
	},
	{
		id:       "builtin-kr-bank-account",
		name:     "Korean Bank Account",
		pattern:  `\b\d{3,4}-\d{2,6}-\d{2,6}\b`,
		category: "pii",
		region:   "kr",
	},
}

// PII: Japan
var piiJP = []patternDef{
	{
		id:       "builtin-jp-my-number-individual",
		name:     "Japanese My Number (Individual)",
		pattern:  `\b\d{4}\s?\d{4}\s?\d{4}\b`,
		category: "pii",
		region:   "jp",
	},
	{
		id:       "builtin-jp-my-number-corporate",
		name:     "Japanese My Number (Corporate)",
		pattern:  `\b\d{13}\b`,
		category: "pii",
		region:   "jp",
	},
	{
		id:       "builtin-jp-phone",
		name:     "Japanese Phone",
		pattern:  `\b0[789]0-\d{4}-\d{4}\b`,
		category: "pii",
		region:   "jp",
	},
}

// PII: Europe
var piiEU = []patternDef{
	{
		id:       "builtin-uk-nin",
		name:     "UK National Insurance Number",
		pattern:  `\b[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z]\s?\d{2}\s?\d{2}\s?\d{2}\s?[A-D]\b`,
		category: "pii",
		region:   "uk",
	},
	{
		id:       "builtin-de-tax-id",
		name:     "German Tax ID (Steuer-ID)",
		pattern:  `\b\d{11}\b`,
		category: "pii",
		region:   "de",
	},
	{
		id:       "builtin-fr-nir",
		name:     "French NIR (Social Security)",
		pattern:  `\b[12]\s?\d{2}\s?\d{2}\s?\d{2}\s?\d{3}\s?\d{3}\s?\d{2}\b`,
		category: "pii",
		region:   "fr",
	},
}

// PII: India
var piiIN = []patternDef{
	{
		id:       "builtin-in-aadhaar",
		name:     "Indian Aadhaar",
		pattern:  `\b\d{4}\s\d{4}\s\d{4}\b`,
		category: "pii",
		region:   "in",
	},
	{
		id:       "builtin-in-pan",
		name:     "Indian PAN",
		pattern:  `\b[A-Z]{5}\d{4}[A-Z]\b`,
		category: "pii",
		region:   "in",
	},
}

// PII: Brazil
var piiBR = []patternDef{
	{
		id:       "builtin-br-cpf",
		name:     "Brazilian CPF",
		pattern:  `\b\d{3}\.\d{3}\.\d{3}-\d{2}\b`,
		category: "pii",
		region:   "br",
	},
}

// PII: Other regions
var piiOther = []patternDef{
	{
		id:       "builtin-ca-sin",
		name:     "Canadian SIN",
		pattern:  `\b\d{3}-\d{3}-\d{3}\b`,
		category: "pii",
		region:   "ca",
	},
	{
		id:       "builtin-au-tfn",
		name:     "Australian TFN",
		pattern:  `\b\d{3}\s?\d{3}\s?\d{2,3}\b`,
		category: "pii",
		region:   "au",
	},
	{
		id:       "builtin-sg-nric",
		name:     "Singapore NRIC/FIN",
		pattern:  `\b[STFGM]\d{7}[A-Z]\b`,
		category: "pii",
		region:   "sg",
	},
	{
		id:       "builtin-hk-id",
		name:     "Hong Kong ID",
		pattern:  `\b[A-Z]{1,2}\d{6}\(?[0-9A]\)?\b`,
		category: "pii",
		region:   "hk",
	},
}

// PII: Global
var piiGlobal = []patternDef{
	{
		id:       "builtin-email",
		name:     "Email Address",
		pattern:  `\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b`,
		category: "pii",
		region:   "global",
	},
}

// Financial
var financial = []patternDef{
	{
		id:       "builtin-credit-card",
		name:     "Credit Card",
		pattern:  `\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2})|35(?:2[89]|[3-8]\d))[- ]?\d{4}[- ]?\d{4}[- ]?\d{3,4}\b`,
		category: "financial",
		region:   "global",
	},
	{
		id:       "builtin-iban",
		name:     "IBAN",
		pattern:  `\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]{0,18})\b`,
		category: "financial",
		region:   "global",
	},
	{
		id:       "builtin-swift-bic",
		name:     "SWIFT/BIC Code",
		pattern:  `\b[A-Z]{6}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b`,
		category: "financial",
		region:   "global",
	},
	{
		id:       "builtin-us-routing",
		name:     "US Routing Number",
		pattern:  `\b[0-3]\d{8}\b`,
		category: "financial",
		region:   "us",
	},
	{
		id:       "builtin-bitcoin-address",
		name:     "Bitcoin Address",
		pattern:  `\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b`,
		category: "financial",
		region:   "global",
	},
	{
		id:       "builtin-ethereum-address",
		name:     "Ethereum Address",
		pattern:  `\b0x[0-9a-fA-F]{40}\b`,
		category: "financial",
		region:   "global",
	},
}

// Healthcare (HIPAA)
var healthcare = []patternDef{
	{
		id:       "builtin-us-npi",
		name:     "US NPI",
		pattern:  `\b\d{10}\b`,
		category: "healthcare",
		region:   "us",
	},
	{
		id:       "builtin-us-dea",
		name:     "US DEA Number",
		pattern:  `\b[ABCDEFGHJKLMNPRSTUXabcdefghjklmnprstux][A-Za-z9]\d{7}\b`,
		category: "healthcare",
		region:   "us",
	},
}

// Secrets: Cloud Providers
var secretCloud = []patternDef{
	{
		id:       "builtin-aws-access-key",
		name:     "AWS Access Key",
		pattern:  `\bAKIA[0-9A-Z]{16}\b`,
		category: "secret",
		region:   "global",
	},
	{
		id:       "builtin-aws-secret-key",
		name:     "AWS Secret Key",
		pattern:  `\b[A-Za-z0-9/+=]{40}\b`,
		category: "secret",
		region:   "global",
	},
	{
		id:       "builtin-gcp-api-key",
		name:     "GCP API Key",
		pattern:  `\bAIza[0-9A-Za-z_-]{35}\b`,
		category: "secret",
		region:   "global",
	},
	{
		id:       "builtin-gcp-service-account",
		name:     "GCP Service Account Key",
		pattern:  `"type"\s*:\s*"service_account"`,
		category: "secret",
		region:   "global",
	},
	{
		id:       "builtin-azure-client-secret",
		name:     "Azure Client Secret",
		pattern:  `\b[a-zA-Z0-9~._-]{34}\b`,
		category: "secret",
		region:   "global",
	},
	{
		id:       "builtin-azure-sas-token",
		name:     "Azure SAS Token",
		pattern:  `sv=\d{4}-\d{2}-\d{2}&[a-zA-Z0-9%&=_.-]+sig=[a-zA-Z0-9%+/=]+`,
		category: "secret",
		region:   "global",
	},
}

// Secrets: AI Providers
var secretAI = []patternDef{
	{
		id:       "builtin-openai-key",
		name:     "OpenAI API Key",
		pattern:  `\bsk-(?:proj-)?[a-zA-Z0-9_-]{20,}\b`,
		category: "secret",
		region:   "global",
	},
	{
		id:       "builtin-anthropic-key",
		name:     "Anthropic API Key",
		pattern:  `\bsk-ant-[a-zA-Z0-9_-]{90,}\b`,
		category: "secret",
		region:   "global",
	},
	{
		id:       "builtin-huggingface-token",
		name:     "HuggingFace Token",
		pattern:  `\bhf_[a-zA-Z0-9]{34}\b`,
		category: "secret",
		region:   "global",
	},
	{
		id:       "builtin-cohere-key",
		name:     "Cohere API Key",
		pattern:  `\b[a-zA-Z0-9]{40}\b`,
		category: "secret",
		region:   "global",
	},
}

// Secrets: Database Connection Strings
var secretDB = []patternDef{
	{
		id:       "builtin-postgres-url",
		name:     "PostgreSQL Connection String",
		pattern:  `postgres(?:ql)?://[^\s:]+:[^\s@]+@[^\s]+`,
		category: "secret",
		region:   "global",
	},
	{
		id:       "builtin-mysql-url",
		name:     "MySQL Connection String",
		pattern:  `mysql://[^\s:]+:[^\s@]+@[^\s]+`,
		category: "secret",
		region:   "global",
	},
	{
		id:       "builtin-mongodb-url",
		name:     "MongoDB Connection String",
		pattern:  `mongodb(?:\+srv)?://[^\s:]+:[^\s@]+@[^\s]+`,
		category: "secret",
		region:   "global",
	},
	{
		id:       "builtin-redis-url",
		name:     "Redis Connection String",
		pattern:  `rediss?://[^\s:]*:[^\s@]+@[^\s]+`,
		category: "secret",
		region:   "global",
	},
	{
		id:       "builtin-jwt-token",
		name:     "JWT Token",
		pattern:  `\beyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`,
		category: "secret",
		region:   "global",
	},
}

// Secrets: SaaS / Developer Tools
var secretSaaS = []patternDef{
	{
		id:       "builtin-github-pat",
		name:     "GitHub PAT",
		pattern:  `\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\b`,
		category: "secret",
		region:   "global",
	},
	{
		id:       "builtin-gitlab-pat",
		name:     "GitLab PAT",
		pattern:  `\bglpat-[A-Za-z0-9_-]{20,}\b`,
		category: "secret",
		region:   "global",
	},
	{
		id:       "builtin-slack-bot-token",
		name:     "Slack Bot Token",
		pattern:  `\bxoxb-[0-9]+-[0-9]+-[a-zA-Z0-9]+\b`,
		category: "secret",
		region:   "global",
	},
	{
		id:       "builtin-slack-webhook",
		name:     "Slack Webhook URL",
		pattern:  `https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[a-zA-Z0-9]+`,
		category: "secret",
		region:   "global",
	},
	{
		id:       "builtin-stripe-secret",
		name:     "Stripe Secret Key",
		pattern:  `\b(?:sk_live|sk_test)_[A-Za-z0-9]{24,}\b`,
		category: "secret",
		region:   "global",
	},
	{
		id:       "builtin-stripe-publishable",
		name:     "Stripe Publishable Key",
		pattern:  `\b(?:pk_live|pk_test)_[A-Za-z0-9]{24,}\b`,
		category: "secret",
		region:   "global",
	},
	{
		id:       "builtin-sendgrid-key",
		name:     "SendGrid API Key",
		pattern:  `\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b`,
		category: "secret",
		region:   "global",
	},
	{
		id:       "builtin-npm-token",
		name:     "npm Token",
		pattern:  `\bnpm_[A-Za-z0-9]{36}\b`,
		category: "secret",
		region:   "global",
	},
	{
		id:       "builtin-pypi-token",
		name:     "PyPI Token",
		pattern:  `\bpypi-[A-Za-z0-9_-]{150,}\b`,
		category: "secret",
		region:   "global",
	},
	{
		id:       "builtin-controlzero-key",
		name:     "Control Zero API Key",
		pattern:  `\bcz_(?:live|test)_[A-Za-z0-9]{20,}\b`,
		category: "secret",
		region:   "global",
	},
}

// Secrets: Infrastructure
var secretInfra = []patternDef{
	{
		id:       "builtin-ssh-private-key",
		name:     "SSH Private Key",
		pattern:  `-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----`,
		category: "secret",
		region:   "global",
	},
	{
		id:       "builtin-pem-certificate",
		name:     "PEM Certificate",
		pattern:  `-----BEGIN CERTIFICATE-----`,
		category: "secret",
		region:   "global",
	},
	{
		id:       "builtin-vault-token",
		name:     "Vault Token",
		pattern:  `\bhvs\.[a-zA-Z0-9_-]{24,}\b`,
		category: "secret",
		region:   "global",
	},
	{
		id:       "builtin-doppler-token",
		name:     "Doppler Token",
		pattern:  `\bdp\.st\.[a-zA-Z0-9]{40,}\b`,
		category: "secret",
		region:   "global",
	},
	{
		id:       "builtin-datadog-api-key",
		name:     "Datadog API Key",
		pattern:  `\b[a-f0-9]{32}\b`,
		category: "secret",
		region:   "global",
	},
	{
		id:       "builtin-sentry-dsn",
		name:     "Sentry DSN",
		pattern:  `https://[a-f0-9]+@[a-z0-9.]+\.ingest\.sentry\.io/\d+`,
		category: "secret",
		region:   "global",
	},
	{
		id:       "builtin-bearer-token",
		name:     "Bearer Token (Authorization Header)",
		pattern:  `[Aa]uthorization:\s*Bearer\s+[A-Za-z0-9_.-]+`,
		category: "secret",
		region:   "global",
	},
	{
		id:       "builtin-amqp-url",
		name:     "AMQP/RabbitMQ Connection String",
		pattern:  `amqps?://[^\s:]+:[^\s@]+@[^\s]+`,
		category: "secret",
		region:   "global",
	},
	{
		id:       "builtin-linear-key",
		name:     "Linear API Key",
		pattern:  `\blin_api_[a-zA-Z0-9]{40,}\b`,
		category: "secret",
		region:   "global",
	},
	{
		id:       "builtin-newrelic-key",
		name:     "New Relic API Key",
		pattern:  `\bNRAK-[A-Z0-9]{27}\b`,
		category: "secret",
		region:   "global",
	},
}

// ---------------------------------------------------------------------------
// Compiled built-in rules (assembled and compiled at package init time)
// ---------------------------------------------------------------------------

var builtinDLPRules []DLPRule

func init() {
	allDefs := make([]patternDef, 0, 128)
	for _, group := range [][]patternDef{
		piiUS, piiKR, piiJP, piiEU, piiIN, piiBR, piiOther,
		piiGlobal,
		financial,
		healthcare,
		secretCloud, secretAI, secretDB, secretSaaS, secretInfra,
	} {
		allDefs = append(allDefs, group...)
	}

	builtinDLPRules = make([]DLPRule, 0, len(allDefs))
	for _, d := range allDefs {
		builtinDLPRules = append(builtinDLPRules, DLPRule{
			ID:       d.id,
			Name:     d.name,
			Pattern:  d.pattern,
			Category: d.category,
			Action:   "detect",
			Region:   d.region,
			compiled: regexp.MustCompile(d.pattern),
		})
	}
}

// ---------------------------------------------------------------------------
// DLPScanner
// ---------------------------------------------------------------------------

// DLPScanner scans text for DLP pattern matches.
//
// Loads built-in patterns on creation. Custom rules can be added via AddRules
// or passed during construction with NewDLPScannerWithRules.
type DLPScanner struct {
	rules []DLPRule
}

// NewDLPScanner creates a scanner with all built-in patterns loaded.
func NewDLPScanner() *DLPScanner {
	s := &DLPScanner{
		rules: make([]DLPRule, len(builtinDLPRules)),
	}
	copy(s.rules, builtinDLPRules)
	return s
}

// NewDLPScannerWithRules creates a scanner with built-in patterns plus the
// given custom rules.
func NewDLPScannerWithRules(customRules []map[string]interface{}) *DLPScanner {
	s := NewDLPScanner()
	s.AddRules(customRules)
	return s
}

// NewDLPScannerNoBuiltins creates a scanner with NO built-in patterns.
// Only custom rules added via AddRules will be active.
func NewDLPScannerNoBuiltins() *DLPScanner {
	return &DLPScanner{}
}

// AddRules adds custom rules on top of existing ones. Each map must contain
// at least a "pattern" key. Invalid regex patterns are silently skipped.
func (s *DLPScanner) AddRules(rawRules []map[string]interface{}) {
	for _, raw := range rawRules {
		patternVal, ok := raw["pattern"]
		if !ok {
			continue
		}
		pattern, ok := patternVal.(string)
		if !ok {
			continue
		}
		compiled, err := regexp.Compile(pattern)
		if err != nil {
			// Skip rules with invalid regex -- safer than crashing the hook.
			continue
		}

		s.rules = append(s.rules, DLPRule{
			ID:       stringFromMap(raw, "id", ""),
			Name:     stringFromMap(raw, "name", stringFromMap(raw, "id", "unnamed")),
			Pattern:  pattern,
			Category: stringFromMap(raw, "category", "pii"),
			Action:   stringFromMap(raw, "action", "detect"),
			Region:   stringFromMap(raw, "region", "global"),
			compiled: compiled,
		})
	}
}

// RuleCount returns the number of loaded rules.
func (s *DLPScanner) RuleCount() int {
	return len(s.rules)
}

// Scan scans text against all loaded DLP rules.
//
// For secret-category rules, MatchedText is a SHA-256 hash of the actual
// matched text. For all other categories, MatchedText contains the literal
// matched string.
func (s *DLPScanner) Scan(text string) []DLPMatch {
	if text == "" || len(s.rules) == 0 {
		return nil
	}

	var matches []DLPMatch
	for i := range s.rules {
		rule := &s.rules[i]
		if rule.compiled == nil {
			continue
		}
		found := rule.compiled.FindAllStringIndex(text, -1)
		if len(found) == 0 {
			continue
		}

		for _, loc := range found {
			rawText := text[loc[0]:loc[1]]

			// Secret-category: hash the matched text, never store plaintext.
			var displayText string
			if rule.Category == "secret" {
				hash := sha256.Sum256([]byte(rawText))
				displayText = hex.EncodeToString(hash[:])
			} else {
				displayText = rawText
			}

			matches = append(matches, DLPMatch{
				RuleID:      rule.ID,
				RuleName:    rule.Name,
				Category:    rule.Category,
				Action:      rule.Action,
				MatchedText: displayText,
				Offset:      loc[0],
				Count:       1,
			})
		}
	}

	return matches
}

// HasBlockingMatch reports whether any match has Action="block".
func HasBlockingMatch(matches []DLPMatch) bool {
	for i := range matches {
		if matches[i].Action == "block" {
			return true
		}
	}
	return false
}

// GetFindingsForAudit converts matches to audit-safe findings.
//
// For secret-category matches, only count is included (no text).
// For other categories, the matched text is included.
func GetFindingsForAudit(matches []DLPMatch) []map[string]interface{} {
	findings := make([]map[string]interface{}, 0, len(matches))
	for i := range matches {
		m := &matches[i]
		entry := map[string]interface{}{
			"rule_id":  m.RuleID,
			"category": m.Category,
			"action":   m.Action,
			"count":    m.Count,
		}
		// Never include matched text for secrets in audit.
		if m.Category != "secret" {
			entry["matched_text"] = m.MatchedText
		}
		findings = append(findings, entry)
	}
	return findings
}

// ---------------------------------------------------------------------------
// ExtractTextFromArgs recursively extracts all string values from a nested
// map/slice structure (typically decoded from JSON tool arguments).
// Non-string leaf values are converted to their string representation.
// ---------------------------------------------------------------------------

// ExtractTextFromArgs flattens nested args into a single scannable string.
func ExtractTextFromArgs(args interface{}) string {
	var parts []string
	extractRecursive(args, &parts)
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += "\n"
		}
		result += p
	}
	return result
}

func extractRecursive(obj interface{}, parts *[]string) {
	switch v := obj.(type) {
	case string:
		*parts = append(*parts, v)
	case map[string]interface{}:
		for _, val := range v {
			extractRecursive(val, parts)
		}
	case []interface{}:
		for _, item := range v {
			extractRecursive(item, parts)
		}
	case nil:
		// skip
	default:
		*parts = append(*parts, fmt.Sprintf("%v", v))
	}
}

// LoadDLPRulesFromPolicy extracts DLP rules from a policy dict's dlp_rules
// section. Returns nil if no dlp_rules section exists.
func LoadDLPRulesFromPolicy(policyData map[string]interface{}) []map[string]interface{} {
	dlpRulesRaw, ok := policyData["dlp_rules"]
	if !ok {
		return nil
	}
	dlpRules, ok := dlpRulesRaw.([]interface{})
	if !ok {
		return nil
	}

	var valid []map[string]interface{}
	for _, item := range dlpRules {
		rule, ok := item.(map[string]interface{})
		if !ok {
			continue
		}
		if _, hasPattern := rule["pattern"]; !hasPattern {
			continue
		}
		// Filter to SDK scope if scopes are specified.
		if scopesRaw, ok := rule["scopes"]; ok {
			if scopes, ok := scopesRaw.([]interface{}); ok && len(scopes) > 0 {
				hasSDK := false
				for _, s := range scopes {
					if str, ok := s.(string); ok && str == "sdk" {
						hasSDK = true
						break
					}
				}
				if !hasSDK {
					continue
				}
			}
		}
		valid = append(valid, rule)
	}
	return valid
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func stringFromMap(m map[string]interface{}, key, fallback string) string {
	v, ok := m[key]
	if !ok {
		return fallback
	}
	s, ok := v.(string)
	if !ok {
		return fallback
	}
	return s
}

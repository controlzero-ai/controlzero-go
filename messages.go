package controlzero

import (
	"os"
	"strings"
)

// In-binary localization pack for the SDK-GENERATED decision reasons
// ( checklist #25, gh#1439). Mirrors the Python SDK
// controlzero/_internal/_messages.py and the Node SDK
// src/internal/messages.ts so the same locale produces the same Korean text
// across SDKs.
//
// Why this exists: the user-facing Reason string is carried end-to-end as
// UTF-8, so an operator can already localize ANY rule by typing the target
// language into that rule's reason: -- or, per-locale, into the new
// reason_localized map (PolicyRule.ReasonLocalized). This pack covers the
// OTHER half: the messages the SDK itself GENERATES for the no-rule-match and
// empty/missing-bundle paths. No runtime i18n library is used (pure map
// lookups), keeping the SDK air-gap safe.
//
// Contract:
//   - The "en" value for NO_RULE_MATCH:* is the single source of truth for the
//     no-match path that now reads it: it MUST stay byte-identical to the
//     legacy hard-coded string so existing reason-regex consumers are
//     unaffected.
//   - English remains the literal default when CONTROLZERO_LOCALE is unset or a
//     locale key is missing.
//   - For the synthetic empty/missing-bundle rules the English text stays on
//     the rule's Reason (bundle output unchanged); the pack supplies ONLY the
//     localized (non-en) override, by reason_code.
//
// KOREAN COPY IS A PROFESSIONAL DRAFT and MUST be reviewed/approved by the customer
// before being presented as final. English is never blocked on it.

const defaultLocale = "en"

// systemMessages maps a message key to {locale -> template}. The Go SDK's
// generated strings carry no placeholders, so no formatting step is needed.
var systemMessages = map[string]map[string]string{
	// No-rule-match fallthrough. Go uses the SHORT legacy form (the Python /
	// Node SDKs carry a longer self-explaining variant); each SDK's en value
	// matches ITS OWN legacy string.
	"NO_RULE_MATCH:deny": {
		"en": "No matching policy rule (fail-closed default)",
		// ko: "일치하는 정책 규칙이 없습니다 (기본 차단)"
		"ko": "일치하는 정책 규칙이 없습니다(기본 차단)",
	},
	"NO_RULE_MATCH:allow": {
		"en": "No matching policy rule (default_action=allow)",
		"ko": "일치하는 정책 규칙이 없습니다(default_action=allow)",
	},
	"NO_RULE_MATCH:warn": {
		"en": "No matching policy rule (default_action=warn)",
		"ko": "일치하는 정책 규칙이 없습니다(default_action=warn)",
	},
	// Synthetic empty / missing-bundle rules: English here is parity-only (the
	// live English stays on the rule's Reason); the enforcer reads ONLY the
	// localized (non-en) value, by reason_code.
	"OBSERVE_MODE_NO_POLICY": {
		"en": "OBSERVE MODE: no policies are active on this project, so " +
			"Control Zero is monitoring and auditing tool calls but NOT " +
			"enforcing -- every call is allowed and logged. Attach a policy " +
			"(or set the empty-project default to deny) in the Control Zero " +
			"dashboard to start enforcing.",
		// ko: "관찰 모드: 이 프로젝트에 활성 정책이 없으므로 ... 차단하지 않습니다 ..."
		"ko": "관찰 모드: 이 프로젝트에 활성 정책이 없으므로 Control Zero는 " +
			"도구 호출을 모니터링하고 감사 기록을 남기지만 차단하지는 " +
			"않습니다 -- 모든 호출이 허용되고 기록됩니다. 시행을 시작하려면 " +
			"Control Zero 대시보드에서 정책을 연결하거나(또는 빈 프로젝트 " +
			"기본값을 deny로 설정) 하십시오.",
	},
	"NO_ACTIVE_POLICIES": {
		"en": "No policies are active on this project. If the dashboard " +
			"shows attached policies, regenerate the policy bundle.",
		// ko: "이 프로젝트에 활성 정책이 없습니다. 대시보드에 연결된 정책이 표시되면 ..."
		"ko": "이 프로젝트에 활성 정책이 없습니다. 대시보드에 연결된 정책이 " +
			"표시되면 정책 번들을 다시 생성하십시오.",
	},
	"BUNDLE_MISSING": {
		"en": "Policy bundle could not be loaded or produced zero enforceable " +
			"rules. Control Zero is failing CLOSED (deny) rather than allowing " +
			"every tool call. Regenerate the policy bundle in the Control Zero " +
			"dashboard; contact support if this persists.",
		// ko: "정책 번들을 로드할 수 없거나 시행 가능한 규칙을 생성하지 못했습니다 ..."
		"ko": "정책 번들을 로드할 수 없거나 시행 가능한 규칙을 생성하지 " +
			"못했습니다(미동기화, 백엔드 연결 불가, 복호화 실패 또는 손상/" +
			"부분/오래된 번들). Control Zero는 모든 호출을 허용하는 대신 " +
			"차단(기본 차단)합니다. Control Zero 대시보드에서 정책 번들을 " +
			"다시 생성하고, 문제가 지속되면 지원팀에 문의하십시오.",
	},
}

// ResolveLocale resolves the active locale. Precedence: explicit arg >
// CONTROLZERO_LOCALE env > "" (English). Lower-cased + trimmed.
func ResolveLocale(explicit string) string {
	if e := strings.TrimSpace(explicit); e != "" {
		return strings.ToLower(e)
	}
	return strings.ToLower(strings.TrimSpace(os.Getenv("CONTROLZERO_LOCALE")))
}

// localeCandidates returns lookup candidates for a locale, most specific first
// (ko-KR -> ["ko-kr", "ko"]) so a pack keyed by the bare primary subtag still
// matches a region-qualified request.
func localeCandidates(locale string) []string {
	loc := strings.ToLower(strings.TrimSpace(locale))
	if loc == "" {
		return nil
	}
	out := []string{loc}
	for _, sep := range []string{"-", "_"} {
		if i := strings.Index(loc, sep); i > 0 {
			primary := loc[:i]
			if primary != "" && primary != loc {
				out = append(out, primary)
			}
			break
		}
	}
	return out
}

// systemMessage returns the fully-resolved system message for key,
// English-default. ok is false only when key is unknown. Used by the no-match
// path where the pack is the source of the English text.
func systemMessage(key, locale string) (string, bool) {
	entry, ok := systemMessages[key]
	if !ok {
		return "", false
	}
	for _, cand := range localeCandidates(ResolveLocale(locale)) {
		if msg, ok := entry[cand]; ok {
			return msg, true
		}
	}
	if msg, ok := entry[defaultLocale]; ok {
		return msg, true
	}
	return "", false
}

// localizedOverride returns ONLY a non-English localized message for key, with
// ok=false otherwise (never falls back to English). Used for the synthetic
// empty/missing-bundle rules whose English text stays on the rule's Reason --
// the override applies only when an actual localized string exists.
func localizedOverride(key, locale string) (string, bool) {
	entry, ok := systemMessages[key]
	if !ok {
		return "", false
	}
	for _, cand := range localeCandidates(ResolveLocale(locale)) {
		if cand == defaultLocale {
			continue
		}
		if msg, ok := entry[cand]; ok {
			return msg, true
		}
	}
	return "", false
}

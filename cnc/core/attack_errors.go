package core

import (
	"errors"
	"fmt"
	"strings"
)

// AttackDisplayError is shown to users; Key selects assets/banners/{theme}/branding/errors/<Key>.txt (TermFX, optional <<$placeholders>>).
type AttackDisplayError struct {
	Key string
	Ctx map[string]string
}

func (e *AttackDisplayError) Error() string {
	if e.Key != "" {
		return "attack:" + e.Key
	}
	return "attack:error"
}

// NewAttackErr builds a branded attack message key. Ctx may be nil.
func NewAttackErr(key string, ctx map[string]string) *AttackDisplayError {
	if ctx == nil {
		ctx = map[string]string{}
	}
	return &AttackDisplayError{Key: key, Ctx: ctx}
}

// attackErrorDefaults used when branding/errors/<key>.txt is missing or empty.
var attackErrorDefaults = map[string]string{
	"attacks_disabled":       "Attacks are currently disabled.",
	"unknown_method":         "Unknown attack method.",
	"method_disabled":        "Method <<$method>> is currently disabled.",
	"vip_required":           "This method requires VIP access.",
	"private_method":         "You do not have access to this method.",
	"non_public_host":        "Target is a non-public address (blocked by server policy).",
	"blacklisted":            "Target is blacklisted.",
	"duration_hard":          "Duration exceeds hard limit of <<$max>> seconds.",
	"duration_soft":          "Duration exceeds soft limit of <<$max>> seconds.",
	"duration_user_max":      "Duration exceeds your max time of <<$max>> seconds.",
	"concurrent_limit":       "You have reached your concurrent attack limit (<<$max>>).",
	"internal_concurrents":   "Failed to check concurrent attacks.",
	"global_slots_full":      "All attack slots are full (<<$used>>/<<$max>>).",
	"internal_global_slots":  "Failed to check global slots.",
	"method_slots_full":      "All <<$method>> slots are full (<<$used>>/<<$max>>).",
	"internal_method_slots":  "Failed to check method slots.",
	"group_slots_full":       "All <<$group>> group slots are full (<<$used>>/<<$max>>).",
	"internal_group_slots":   "Failed to check group slots.",
	"group_maxtime":          "Duration exceeds <<$group>> group limit of <<$max>> seconds.",
	"spam_general":           "You are sending attacks too quickly. Please wait.",
	"spam_target":            "You are attacking this target too frequently. Please wait.",
	"db_log_failed":          "Failed to record attack (database).",
	"host_empty":             "Target host is empty.",
	"host_not_url_or_ip":     "Target must be a valid IP address or an http(s):// URL.",
	"host_invalid_url":       "Invalid URL.",
	"host_bad_scheme":        "URL must use http:// or https://.",
	"host_missing_host":      "URL must include a host.",
	"host_dot_required":      "URL host must contain a dot (e.g. example.com).",
}

// ReadThemedBannerStatic loads assets/banners/{theme}/subpath with fallback to default theme.
func ReadThemedBannerStatic(theme, subpath string) string {
	theme = strings.TrimSpace(theme)
	if theme == "" {
		theme = "default"
	}
	path := fmt.Sprintf("assets/banners/%s/%s", theme, subpath)
	content := ReadBannerFile(path)
	if content != "" || theme == "default" {
		return content
	}
	return ReadBannerFile(fmt.Sprintf("assets/banners/default/%s", subpath))
}

// FormatBrandedAttackError renders branding/errors/<key>.txt with TermFX, or the default string for that key.
func FormatBrandedAttackError(theme, key string, ctx map[string]string) string {
	key = strings.TrimSpace(key)
	if key == "" {
		return "An error occurred."
	}
	raw := strings.TrimSpace(ReadThemedBannerStatic(theme, "branding/errors/"+key+".txt"))
	if raw == "" {
		raw = attackErrorDefaults[key]
	}
	if raw == "" {
		return "An error occurred."
	}
	if ctx == nil {
		ctx = map[string]string{}
	}
	return strings.TrimSpace(RenderTermFX(raw, ctx))
}

// FormatAttackUserError resolves AttackDisplayError to text; otherwise returns err.Error().
func FormatAttackUserError(s *Session, err error) string {
	var ade *AttackDisplayError
	if errors.As(err, &ade) {
		return FormatBrandedAttackError(s.effectiveTheme(), ade.Key, ade.Ctx)
	}
	return err.Error()
}

// FormatAttackUserErrorTheme is like FormatAttackUserError but uses an explicit theme name (e.g. API user theme).
func FormatAttackUserErrorTheme(theme string, err error) string {
	var ade *AttackDisplayError
	if errors.As(err, &ade) {
		return FormatBrandedAttackError(theme, ade.Key, ade.Ctx)
	}
	return err.Error()
}

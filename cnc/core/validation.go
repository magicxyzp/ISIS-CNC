package core

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strings"
)

var usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9_]{1,32}$`)

// ValidateUsername returns normalized lowercase username or an error.
func ValidateUsername(name string) (string, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", fmt.Errorf("username cannot be empty")
	}
	if strings.ContainsAny(name, " \t\r\n") {
		return "", fmt.Errorf("username cannot contain spaces")
	}
	if !usernamePattern.MatchString(name) {
		return "", fmt.Errorf("username must be 1-32 chars: letters, digits, underscore only")
	}
	return strings.ToLower(name), nil
}

// ValidateAttackTargetHost requires a literal IP (v4/v6) or an absolute http(s) URL whose host is an IP or contains at least one dot (e.g. example.com).
func ValidateAttackTargetHost(host string) error {
	host = strings.TrimSpace(host)
	if host == "" {
		return NewAttackErr("host_empty", nil)
	}
	if net.ParseIP(host) != nil {
		return nil
	}
	lower := strings.ToLower(host)
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		return NewAttackErr("host_not_url_or_ip", nil)
	}
	u, err := url.Parse(host)
	if err != nil || u.Host == "" {
		return NewAttackErr("host_invalid_url", nil)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return NewAttackErr("host_bad_scheme", nil)
	}
	h := u.Hostname()
	if h == "" {
		return NewAttackErr("host_missing_host", nil)
	}
	if net.ParseIP(h) != nil {
		return nil
	}
	if !strings.Contains(h, ".") {
		return NewAttackErr("host_dot_required", nil)
	}
	return nil
}

// AttackTargetLookupName returns the hostname or IP to use for DNS / private-IP checks (strips URL scheme/path).
func AttackTargetLookupName(host string) string {
	host = strings.TrimSpace(host)
	if net.ParseIP(host) != nil {
		return host
	}
	lower := strings.ToLower(host)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		if u, err := url.Parse(host); err == nil {
			if h := u.Hostname(); h != "" {
				return h
			}
		}
	}
	return host
}

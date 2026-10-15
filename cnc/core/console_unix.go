//go:build !windows

package core

// EnableANSI is a no-op on non-Windows systems — ANSI codes work natively.
func EnableANSI() {}

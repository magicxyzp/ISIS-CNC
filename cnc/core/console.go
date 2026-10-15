//go:build windows

package core

import (
	"os"

	"golang.org/x/sys/windows"
)

// EnableANSI enables Virtual Terminal Processing on Windows so ANSI escape
// codes render correctly in cmd.exe and PowerShell. No-op on non-Windows.
func EnableANSI() {
	stdout := windows.Handle(os.Stdout.Fd())
	var mode uint32
	if err := windows.GetConsoleMode(stdout, &mode); err != nil {
		return
	}
	windows.SetConsoleMode(stdout, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
}

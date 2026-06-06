//go:build !windows

package main

import (
	"fmt"
)

const serviceName = "twsnmpv3proxy"

// runService is a stub that does nothing on non-Windows platforms.
func runService(configPath string, localIP string) {
	// Dummy implementation; will not be called because isWindowsService() returns false on non-Windows.
}

// handleServiceCommand returns an error since Windows Service actions are Windows-only.
func handleServiceCommand(cmd, configPath, localIP string) error {
	return fmt.Errorf("service commands (install, uninstall, start, stop) are only supported on Windows")
}

// isWindowsService returns false on non-Windows platforms.
func isWindowsService() bool {
	return false
}

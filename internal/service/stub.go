//go:build !windows && !linux && !darwin
// +build !windows,!linux,!darwin

// Package service provides platform-specific service support.
// This is the stub for platforms other than Windows and Linux.
package service

import (
	"errors"

	"dnn-daemon/internal/config"
)

// IsWindowsService returns false on non-Windows platforms
func IsWindowsService() bool {
	return false
}

// RunService is not supported on non-Windows platforms
func RunService(cfg *config.Config, isDebug bool) error {
	return errors.New("Windows service not supported on this platform")
}

// InstallService is not supported on non-Windows platforms
func InstallService(exePath, configPath string) error {
	return errors.New("Windows service not supported on this platform")
}

// UninstallService is not supported on non-Windows platforms
func UninstallService() error {
	return errors.New("Windows service not supported on this platform")
}

// DefaultConfigPath returns the default config path for Linux
func DefaultConfigPath() string {
	return "/etc/dnn/dnn-daemon.yaml"
}

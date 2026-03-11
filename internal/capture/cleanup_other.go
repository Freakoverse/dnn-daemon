//go:build !windows

package capture

// CleanupWinDivert is a no-op on non-Windows platforms.
// On Windows, this removes the temporary directory containing
// extracted WinDivert driver files.
func CleanupWinDivert() {}

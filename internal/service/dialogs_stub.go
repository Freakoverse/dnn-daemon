//go:build !windows && !linux && !darwin
// +build !windows,!linux,!darwin

package service

// Action represents user's choice from main dialog
type Action int

const (
	ActionCancel    Action = 0
	ActionInstall   Action = 1
	ActionUninstall Action = 2
)

// Dialog button IDs
const (
	IDYES    = 6
	IDNO     = 7
	IDCANCEL = 2
)

// ShowMainActionDialog returns cancel on unsupported platforms
func ShowMainActionDialog(isInstalled bool) Action {
	return ActionCancel
}

// ShowNodeConfigDialog returns nil on unsupported platforms
func ShowNodeConfigDialog(defaultNodes []string) []string {
	return defaultNodes
}

// ShowInstallConfirmation returns false on unsupported platforms
func ShowInstallConfirmation() bool {
	return false
}

// ShowInstallSuccess does nothing on unsupported platforms
func ShowInstallSuccess() {}

// ShowInstallError does nothing on unsupported platforms
func ShowInstallError(err error) {}

// ShowUninstallConfirmation returns false on unsupported platforms
func ShowUninstallConfirmation() bool {
	return false
}

// ShowUninstallSuccess does nothing on unsupported platforms
func ShowUninstallSuccess() {}

// ShowAlreadyInstalled returns cancel on unsupported platforms
func ShowAlreadyInstalled() int {
	return IDCANCEL
}

// IsAdmin returns false on unsupported platforms
func IsAdmin() bool {
	return false
}

// RequestElevation does nothing on unsupported platforms
func RequestElevation() error {
	return nil
}

// IsServiceInstalled returns false on unsupported platforms
func IsServiceInstalled() bool {
	return false
}

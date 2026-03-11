//go:build darwin
// +build darwin

package service

import (
	"os/exec"
	"strings"
)

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

// osascript runs an AppleScript and returns the output
func osascript(script string) (string, error) {
	cmd := exec.Command("osascript", "-e", script)
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}

// ShowMainActionDialog shows the main Install/Uninstall/Cancel dialog
func ShowMainActionDialog(isInstalled bool) Action {
	var message string
	if isInstalled {
		message = "DNN Daemon is currently installed.\\n\\nChoose an action:"
	} else {
		message = "Welcome to DNN Daemon!\\n\\n" +
			"This will install the DNN Daemon, allowing you to access freedom domains on the DNN network.\\n\\n" +
			"The installation will:\\n" +
			"• Install a local Certificate Authority\\n" +
			"• Start the DNN service (pf DNS interception)"
	}

	script := `tell application "System Events"
		activate
		set choice to button returned of (display dialog "` + message + `" buttons {"Cancel", "Uninstall", "Install"} default button "Install" with title "DNN Daemon")
		return choice
	end tell`

	result, err := osascript(script)
	if err != nil {
		return ActionCancel
	}

	switch result {
	case "Install":
		return ActionInstall
	case "Uninstall":
		return ActionUninstall
	default:
		return ActionCancel
	}
}

// ShowNodeConfigDialog shows a dialog for configuring DNN nodes
func ShowNodeConfigDialog(defaultNodes []string) []string {
	defaultText := strings.Join(defaultNodes, ", ")

	script := `tell application "System Events"
		activate
		set result to text returned of (display dialog "Enter DNN node URLs (comma-separated):\n\nThese servers resolve DNN domain names.\nThe daemon will also discover additional nodes automatically." default answer "` + escapeAppleScript(defaultText) + `" with title "DNN Node Configuration")
		return result
	end tell`

	result, err := osascript(script)
	if err != nil {
		return nil // User cancelled
	}

	return parseNodes(result)
}

// ShowInstallConfirmation shows the install confirmation dialog
func ShowInstallConfirmation() bool {
	script := `tell application "System Events"
		activate
		set choice to button returned of (display dialog "Install DNN Daemon?\n\nThis will configure your system to access DNN domains." buttons {"Cancel", "Install"} default button "Install" with title "DNN Daemon Installation")
		return choice
	end tell`

	result, err := osascript(script)
	return err == nil && result == "Install"
}

// ShowInstallSuccess shows the success message
func ShowInstallSuccess() {
	script := `tell application "System Events"
		activate
		display dialog "DNN Daemon has been installed successfully!\n\nYou can now access DNN domains in your browser.\n\nTo uninstall, run this program again." buttons {"OK"} default button "OK" with title "DNN Daemon Installed" with icon note
	end tell`
	osascript(script)
}

// ShowInstallError shows an error message
func ShowInstallError(err error) {
	message := escapeAppleScript("Failed to install DNN Daemon:\\n\\n" + err.Error())
	script := `tell application "System Events"
		activate
		display dialog "` + message + `" buttons {"OK"} default button "OK" with title "Installation Failed" with icon stop
	end tell`
	osascript(script)
}

// ShowUninstallConfirmation shows the uninstall confirmation dialog
func ShowUninstallConfirmation() bool {
	script := `tell application "System Events"
		activate
		set choice to button returned of (display dialog "Do you want to uninstall DNN Daemon?\n\nThis will remove the DNN service and CA certificate." buttons {"Cancel", "Uninstall"} default button "Uninstall" with title "Uninstall DNN Daemon")
		return choice
	end tell`

	result, err := osascript(script)
	return err == nil && result == "Uninstall"
}

// ShowUninstallSuccess shows the uninstall success message
func ShowUninstallSuccess() {
	script := `tell application "System Events"
		activate
		display dialog "DNN Daemon has been uninstalled successfully." buttons {"OK"} default button "OK" with title "DNN Daemon Uninstalled" with icon note
	end tell`
	osascript(script)
}

// ShowAlreadyInstalled shows a dialog when already installed
func ShowAlreadyInstalled() int {
	// Not used in new flow, but kept for compatibility
	return IDYES
}

// Helper functions

func parseNodes(output string) []string {
	result := strings.TrimSpace(output)
	parts := strings.Split(result, ",")
	var nodes []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			nodes = append(nodes, part)
		}
	}
	if len(nodes) == 0 {
		return nil
	}
	return nodes
}

func escapeAppleScript(s string) string {
	// Escape quotes for AppleScript
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	return s
}

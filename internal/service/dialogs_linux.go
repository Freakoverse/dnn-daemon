//go:build linux
// +build linux

package service

import (
	"fmt"
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

// hasZenity checks if zenity is available
func hasZenity() bool {
	_, err := exec.LookPath("zenity")
	return err == nil
}

// hasKdialog checks if kdialog is available
func hasKdialog() bool {
	_, err := exec.LookPath("kdialog")
	return err == nil
}

// ShowMainActionDialog shows the main Install/Uninstall/Cancel dialog
func ShowMainActionDialog(isInstalled bool) Action {
	var message string
	if isInstalled {
		message = "DNN Daemon is currently installed.\n\nChoose an action:"
	} else {
		message = "Welcome to DNN Daemon!\n\n" +
			"This will install the DNN Daemon, allowing you to access\n" +
			"freedom domains on the DNN network.\n\n" +
			"The installation will:\n" +
			"• Install a local Certificate Authority\n" +
			"• Start the DNN service (iptables DNS interception)"
	}

	if hasZenity() {
		// Use zenity list dialog
		cmd := exec.Command("zenity", "--list",
			"--title=DNN Daemon",
			"--text="+message,
			"--column=Action",
			"--column=Description",
			"Install", "Install or reinstall DNN Daemon",
			"Uninstall", "Remove DNN Daemon from system",
			"--width=400", "--height=300")
		output, err := cmd.Output()
		if err != nil {
			return ActionCancel
		}
		result := strings.TrimSpace(string(output))
		switch result {
		case "Install":
			return ActionInstall
		case "Uninstall":
			return ActionUninstall
		default:
			return ActionCancel
		}
	}

	if hasKdialog() {
		// Use kdialog
		cmd := exec.Command("kdialog", "--menu", message,
			"install", "Install DNN Daemon",
			"uninstall", "Uninstall DNN Daemon",
			"--title", "DNN Daemon")
		output, err := cmd.Output()
		if err != nil {
			return ActionCancel
		}
		result := strings.TrimSpace(string(output))
		switch result {
		case "install":
			return ActionInstall
		case "uninstall":
			return ActionUninstall
		default:
			return ActionCancel
		}
	}

	// Fall back to terminal prompt
	return terminalActionPrompt(isInstalled)
}

// ShowNodeConfigDialog shows a dialog for configuring DNN nodes
func ShowNodeConfigDialog(defaultNodes []string) []string {
	defaultText := strings.Join(defaultNodes, ", ")

	if hasZenity() {
		cmd := exec.Command("zenity", "--entry",
			"--title=DNN Node Configuration",
			"--text=Enter DNN node URLs (comma-separated):\n\nThese servers resolve DNN domain names.\nThe daemon will also discover additional nodes automatically.",
			"--entry-text="+defaultText,
			"--width=500")
		output, err := cmd.Output()
		if err != nil {
			return nil // User cancelled
		}
		return parseNodes(string(output))
	}

	if hasKdialog() {
		cmd := exec.Command("kdialog", "--inputbox",
			"Enter DNN node URLs (comma-separated):\n\nThese servers resolve DNN domain names.",
			defaultText,
			"--title", "DNN Node Configuration")
		output, err := cmd.Output()
		if err != nil {
			return nil
		}
		return parseNodes(string(output))
	}

	// Terminal fallback
	return terminalNodePrompt(defaultNodes)
}

// ShowInstallConfirmation shows the install confirmation dialog
func ShowInstallConfirmation() bool {
	if hasZenity() {
		cmd := exec.Command("zenity", "--question",
			"--title=DNN Daemon Installation",
			"--text=Install DNN Daemon?\n\nThis will configure your system to access DNN domains.",
			"--ok-label=Install", "--cancel-label=Cancel")
		return cmd.Run() == nil
	}

	if hasKdialog() {
		cmd := exec.Command("kdialog", "--yesno",
			"Install DNN Daemon?\n\nThis will configure your system to access DNN domains.",
			"--title", "DNN Daemon Installation",
			"--yes-label", "Install", "--no-label", "Cancel")
		return cmd.Run() == nil
	}

	return true // Terminal mode - just proceed
}

// ShowInstallSuccess shows the success message
func ShowInstallSuccess() {
	message := "DNN Daemon has been installed successfully!\n\n" +
		"You can now access DNN domains in your browser.\n\n" +
		"To uninstall, run this program again."

	if hasZenity() {
		exec.Command("zenity", "--info",
			"--title=DNN Daemon Installed",
			"--text="+message).Run()
		return
	}

	if hasKdialog() {
		exec.Command("kdialog", "--msgbox", message,
			"--title", "DNN Daemon Installed").Run()
		return
	}

	// Terminal
	println("\n✓ " + message)
}

// ShowInstallError shows an error message
func ShowInstallError(err error) {
	message := "Failed to install DNN Daemon:\n\n" + err.Error()

	if hasZenity() {
		exec.Command("zenity", "--error",
			"--title=Installation Failed",
			"--text="+message).Run()
		return
	}

	if hasKdialog() {
		exec.Command("kdialog", "--error", message,
			"--title", "Installation Failed").Run()
		return
	}

	// Terminal
	println("\n✗ " + message)
}

// ShowUninstallConfirmation shows the uninstall confirmation dialog
func ShowUninstallConfirmation() bool {
	if hasZenity() {
		cmd := exec.Command("zenity", "--question",
			"--title=Uninstall DNN Daemon",
			"--text=Do you want to uninstall DNN Daemon?\n\nThis will remove the DNN service and CA certificate.")
		return cmd.Run() == nil
	}

	if hasKdialog() {
		cmd := exec.Command("kdialog", "--yesno",
			"Do you want to uninstall DNN Daemon?",
			"--title", "Uninstall DNN Daemon")
		return cmd.Run() == nil
	}

	return true
}

// ShowUninstallSuccess shows the uninstall success message
func ShowUninstallSuccess() {
	message := "DNN Daemon has been uninstalled successfully."

	if hasZenity() {
		exec.Command("zenity", "--info",
			"--title=DNN Daemon Uninstalled",
			"--text="+message).Run()
		return
	}

	if hasKdialog() {
		exec.Command("kdialog", "--msgbox", message,
			"--title", "DNN Daemon Uninstalled").Run()
		return
	}

	// Terminal
	println("\n✓ " + message)
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

func terminalActionPrompt(isInstalled bool) Action {
	if isInstalled {
		println("DNN Daemon is currently installed.")
	} else {
		println("Welcome to DNN Daemon!")
	}
	println("\n1. Install")
	println("2. Uninstall")
	println("3. Cancel")
	print("\nChoose an option (1-3): ")

	var choice int
	_, err := Scanf("%d", &choice)
	if err != nil {
		return ActionCancel
	}

	switch choice {
	case 1:
		return ActionInstall
	case 2:
		return ActionUninstall
	default:
		return ActionCancel
	}
}

func terminalNodePrompt(defaultNodes []string) []string {
	defaultText := strings.Join(defaultNodes, ", ")
	println("\nEnter DNN node URLs (comma-separated)")
	println("Default: " + defaultText)
	print("Nodes (press Enter for default): ")

	var input string
	_, err := Scanf("%s", &input)
	if err != nil || input == "" {
		return defaultNodes
	}
	return parseNodes(input)
}

// Scanf is a simple wrapper for terminal input
func Scanf(format string, a ...interface{}) (int, error) {
	return fmt.Scanf(format, a...)
}

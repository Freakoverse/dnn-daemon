//go:build windows
// +build windows

package service

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows/svc/mgr"
)

var (
	user32          = syscall.NewLazyDLL("user32.dll")
	procMessageBoxW = user32.NewProc("MessageBoxW")
)

// MessageBox flags
const (
	MB_OK              = 0x00000000
	MB_OKCANCEL        = 0x00000001
	MB_YESNO           = 0x00000004
	MB_YESNOCANCEL     = 0x00000003
	MB_ICONERROR       = 0x00000010
	MB_ICONQUESTION    = 0x00000020
	MB_ICONWARNING     = 0x00000030
	MB_ICONINFORMATION = 0x00000040
	IDOK               = 1
	IDCANCEL           = 2
	IDYES              = 6
	IDNO               = 7
)

// Action represents user's choice from main dialog
type Action int

const (
	ActionCancel    Action = 0
	ActionInstall   Action = 1
	ActionUninstall Action = 2
)

// ShowMainActionDialog shows the main Install/Uninstall/Cancel dialog
// Returns the action chosen by the user
func ShowMainActionDialog(isInstalled bool) Action {
	var message string
	if isInstalled {
		message = "DNN Daemon is currently installed.\n\n" +
			"Choose an action:\n" +
			"• Yes = Reinstall (configure nodes)\n" +
			"• No = Uninstall\n" +
			"• Cancel = Exit"
	} else {
		message = "Welcome to DNN Daemon!\n\n" +
			"This will install the DNN Daemon, allowing you to access\n" +
			"freedom domains on the DNN network.\n\n" +
			"The installation will:\n" +
			"• Install a local Certificate Authority\n" +
			"• Start the DNN service (WinDivert DNS interception)\n\n" +
			"Click Yes to continue, No to uninstall, or Cancel to exit."
	}

	result := MessageBox(
		"DNN Daemon",
		message,
		MB_YESNOCANCEL|MB_ICONQUESTION,
	)

	switch result {
	case IDYES:
		return ActionInstall
	case IDNO:
		return ActionUninstall
	default:
		return ActionCancel
	}
}

// MessageBox shows a Windows message box and returns the button clicked
func MessageBox(title, message string, flags uintptr) int {
	titlePtr, _ := syscall.UTF16PtrFromString(title)
	messagePtr, _ := syscall.UTF16PtrFromString(message)

	ret, _, _ := procMessageBoxW.Call(
		0,
		uintptr(unsafe.Pointer(messagePtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		flags,
	)

	return int(ret)
}

// ShowInstallConfirmation shows the install confirmation dialog
// Returns true if user clicked Yes
func ShowInstallConfirmation() bool {
	result := MessageBox(
		"DNN Daemon Installation",
		"This will install the DNN Daemon service, allowing you to access freedom domains on the DNN network.\n\n"+
			"The installation will:\n"+
			"• Install a local Certificate Authority (for HTTPS)\n"+
			"• Start the DNN Daemon as a Windows service\n"+
			"• Use WinDivert for transparent DNS interception\n\n"+
			"Do you want to continue?",
		MB_YESNO|MB_ICONQUESTION,
	)
	return result == IDYES
}

// ShowInstallSuccess shows the success message
func ShowInstallSuccess() {
	MessageBox(
		"DNN Daemon Installed",
		"DNN Daemon has been installed successfully!\n\n"+
			"You can now access DNN domains in your browser.\n\n"+
			"To uninstall, double-click this exe again.",
		MB_OK|MB_ICONINFORMATION,
	)
}

// ShowInstallError shows an error message
func ShowInstallError(err error) {
	MessageBox(
		"DNN Daemon Installation Failed",
		"Failed to install DNN Daemon:\n\n"+err.Error()+"\n\n"+
			"Make sure you are running as Administrator.",
		MB_OK|MB_ICONERROR,
	)
}

// ShowUninstallConfirmation shows the uninstall confirmation dialog
func ShowUninstallConfirmation() bool {
	result := MessageBox(
		"DNN Daemon Uninstallation",
		"Do you want to uninstall the DNN Daemon?\n\n"+
			"This will:\n"+
			"• Stop and remove the DNN service\n"+
			"• Remove the DNN Certificate Authority",
		MB_YESNO|MB_ICONQUESTION,
	)
	return result == IDYES
}

// ShowUninstallSuccess shows the uninstall success message
func ShowUninstallSuccess() {
	MessageBox(
		"DNN Daemon Uninstalled",
		"DNN Daemon has been uninstalled successfully.\n\n"+
			"The DNN service and CA certificate have been removed.",
		MB_OK|MB_ICONINFORMATION,
	)
}

// ShowAlreadyInstalled shows a dialog when already installed
func ShowAlreadyInstalled() int {
	return MessageBox(
		"DNN Daemon",
		"DNN Daemon is already installed.\n\n"+
			"Would you like to uninstall it?",
		MB_YESNO|MB_ICONQUESTION,
	)
}

// IsServiceInstalled checks if the DNN service is already installed
func IsServiceInstalled() bool {
	m, err := mgr.Connect()
	if err != nil {
		return false
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return false
	}
	s.Close()
	return true
}

// IsAdmin checks if the current process has admin privileges
func IsAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	return err == nil
}

// RequestElevation re-launches the current executable with admin privileges
func RequestElevation() error {
	verb := "runas"
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	verbPtr, _ := syscall.UTF16PtrFromString(verb)
	exePtr, _ := syscall.UTF16PtrFromString(exe)
	cwdPtr, _ := syscall.UTF16PtrFromString("")
	argPtr, _ := syscall.UTF16PtrFromString("")

	shell32 := syscall.NewLazyDLL("shell32.dll")
	shellExecute := shell32.NewProc("ShellExecuteW")

	ret, _, _ := shellExecute.Call(
		0,
		uintptr(unsafe.Pointer(verbPtr)),
		uintptr(unsafe.Pointer(exePtr)),
		uintptr(unsafe.Pointer(argPtr)),
		uintptr(unsafe.Pointer(cwdPtr)),
		1, // SW_SHOWNORMAL
	)

	if ret <= 32 {
		return fmt.Errorf("ShellExecute failed with code %d", ret)
	}
	return nil
}

// ShowNodeConfigDialog shows a dialog for configuring DNN nodes
// Uses VBScript InputBox for text input (no external dependencies)
// Returns nil if user cancels, or the list of nodes
func ShowNodeConfigDialog(defaultNodes []string) []string {
	// Join nodes with commas for display
	defaultText := strings.Join(defaultNodes, ", ")

	// Create VBScript to show InputBox
	script := fmt.Sprintf(`
result = InputBox("Enter DNN node URLs (comma-separated):" & vbCrLf & vbCrLf & _
	"These servers resolve DNN domain names." & vbCrLf & _
	"The daemon will also discover additional nodes automatically.", _
	"DNN Node Configuration", _
	"%s")
If IsEmpty(result) Then
	WScript.Echo "CANCELLED"
Else
	WScript.Echo result
End If
`, escapeVBString(defaultText))

	// Write script to temp file
	tmpFile := os.TempDir() + "\\dnn_input.vbs"
	if err := os.WriteFile(tmpFile, []byte(script), 0644); err != nil {
		return defaultNodes // Fall back to defaults on error
	}
	defer os.Remove(tmpFile)

	// Execute and capture output
	cmd := exec.Command("cscript", "//Nologo", tmpFile)
	output, err := cmd.Output()
	if err != nil {
		return defaultNodes
	}

	result := strings.TrimSpace(string(output))
	if result == "CANCELLED" {
		return nil
	}

	// Parse the result - split by comma and filter empty
	parts := strings.Split(result, ",")
	var nodes []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			nodes = append(nodes, part)
		}
	}

	if len(nodes) == 0 {
		return defaultNodes
	}
	return nodes
}

// escapeVBString escapes a string for use in VBScript
func escapeVBString(s string) string {
	// Replace quotes
	return strings.ReplaceAll(s, "\"", "\"\"")
}

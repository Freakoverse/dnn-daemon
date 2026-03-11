//go:build darwin
// +build darwin

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const serviceName = "xyz.dnn.daemon"
const plistPath = "/Library/LaunchDaemons/xyz.dnn.daemon.plist"

// DefaultConfigPath returns the default config path for macOS
func DefaultConfigPath() string {
	return "/usr/local/etc/dnn/dnn-daemon.yaml"
}

// IsWindowsService always returns false on macOS
func IsWindowsService() bool {
	return false
}

// IsServiceInstalled checks if the launchd service is installed
func IsServiceInstalled() bool {
	_, err := os.Stat(plistPath)
	return err == nil
}

// IsAdmin checks if running as root
func IsAdmin() bool {
	return os.Getuid() == 0
}

// RequestElevation re-launches with osascript for graphical sudo
func RequestElevation() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	// Use osascript to run with administrator privileges
	script := fmt.Sprintf(`do shell script "%s" with administrator privileges`, exe)
	cmd := exec.Command("osascript", "-e", script)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// InstallService installs and starts the launchd service
func InstallService(exePath, configPath string) error {
	// 1. Copy binary to /usr/local/bin
	targetPath := "/usr/local/bin/dnn-daemon"
	if err := copyFile(exePath, targetPath); err != nil {
		return fmt.Errorf("failed to copy binary: %w", err)
	}
	if err := os.Chmod(targetPath, 0755); err != nil {
		return fmt.Errorf("failed to chmod binary: %w", err)
	}

	// 2. Create launchd plist
	plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
        <string>--service</string>
        <string>--config</string>
        <string>%s</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/var/log/dnn-daemon.log</string>
    <key>StandardErrorPath</key>
    <string>/var/log/dnn-daemon.error.log</string>
</dict>
</plist>
`, serviceName, targetPath, configPath)

	if err := os.WriteFile(plistPath, []byte(plistContent), 0644); err != nil {
		return fmt.Errorf("failed to write plist: %w", err)
	}

	// 3. Install CA certificate
	if err := installCA(); err != nil {
		return fmt.Errorf("failed to install CA: %w", err)
	}

	// 4. Add IPv6 route for fd00::/8 to localhost (for transport interception)
	fmt.Println("Adding IPv6 route for transport interception...")
	addRoute := exec.Command("route", "-n", "add", "-inet6", "fd00::/8", "::1")
	if err := addRoute.Run(); err != nil {
		// Route might already exist
		fmt.Printf("Warning: Failed to add IPv6 route (may already exist): %v\n", err)
	} else {
		fmt.Println("IPv6 route added for fd00::/8")
	}

	// 5. Load and start service (pf rules managed by daemon)
	if err := exec.Command("launchctl", "load", plistPath).Run(); err != nil {
		return fmt.Errorf("failed to load service: %w", err)
	}

	fmt.Println("DNN Daemon installed successfully!")
	fmt.Println("Note: DNS interception via pf (no system DNS modification)")

	return nil
}

// UninstallService stops and removes the launchd service
func UninstallService() error {
	// Stop and unload service
	exec.Command("launchctl", "unload", plistPath).Run()

	// Remove plist
	os.Remove(plistPath)

	// Remove pf anchor file (if exists)
	os.Remove("/etc/pf.anchors/dnn")

	// Remove IPv6 route
	fmt.Println("Removing IPv6 route...")
	exec.Command("route", "-n", "delete", "-inet6", "fd00::/8", "::1").Run()

	// Remove CA
	uninstallCA()

	// Remove binary
	os.Remove("/usr/local/bin/dnn-daemon")

	fmt.Println("DNN Daemon uninstalled successfully!")
	fmt.Println("Note: pf rules were managed by the daemon and removed on stop")

	return nil
}

// RunService runs the daemon (called with --service flag)
func RunService(cfg interface{}, debug bool) error {
	// On macOS, just run in foreground - launchd handles daemonization
	return fmt.Errorf("use foreground mode on macOS")
}

func installCA() error {
	caDir := "/usr/local/etc/dnn"
	caCertPath := filepath.Join(caDir, "dnn-ca.crt")

	// Ensure CA directory exists
	if err := os.MkdirAll(caDir, 0755); err != nil {
		return err
	}

	// Check if CA exists
	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		// CA generation is handled by certgen package
		return nil
	}

	// Add to System Keychain
	cmd := exec.Command("security", "add-trusted-cert", "-d", "-r", "trustRoot",
		"-k", "/Library/Keychains/System.keychain", caCertPath)
	return cmd.Run()
}

func uninstallCA() {
	// Remove from System Keychain
	// This requires finding the cert by name first
	exec.Command("security", "delete-certificate", "-c", "DNN Local CA",
		"/Library/Keychains/System.keychain").Run()
}

// Note: configureDNS, restoreDNS, and splitLines removed - pf redirect is handled by capture module

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

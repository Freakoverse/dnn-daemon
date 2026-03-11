//go:build linux
// +build linux

package service

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

const serviceName = "dnn-daemon"
const serviceFile = "/etc/systemd/system/dnn-daemon.service"

// DefaultConfigPath returns the default config path for Linux
func DefaultConfigPath() string {
	return "/etc/dnn/dnn-daemon.yaml"
}

// IsWindowsService always returns false on Linux
func IsWindowsService() bool {
	return false
}

// IsServiceInstalled checks if the systemd service is installed
func IsServiceInstalled() bool {
	_, err := os.Stat(serviceFile)
	return err == nil
}

// IsAdmin checks if running as root
func IsAdmin() bool {
	return os.Getuid() == 0
}

// RequestElevation re-launches with pkexec (graphical sudo)
func RequestElevation() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}

	// Try pkexec first (graphical), fall back to sudo
	if _, err := exec.LookPath("pkexec"); err == nil {
		cmd := exec.Command("pkexec", exe)
		cmd.Stdin = os.Stdin
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		return cmd.Run()
	}

	// Fall back to sudo
	cmd := exec.Command("sudo", exe)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

// InstallService installs and starts the systemd service
func InstallService(exePath, configPath string) error {
	// 1. Copy binary to /usr/local/bin
	targetPath := "/usr/local/bin/dnn-daemon"
	if err := copyFile(exePath, targetPath); err != nil {
		return fmt.Errorf("failed to copy binary: %w", err)
	}
	if err := os.Chmod(targetPath, 0755); err != nil {
		return fmt.Errorf("failed to chmod binary: %w", err)
	}

	// 2. Create systemd service file
	serviceContent := fmt.Sprintf(`[Unit]
Description=DNN Daemon - Decentralized Name Network (iptables DNS interception)
After=network.target

[Service]
Type=simple
ExecStart=%s --service --config %s
Restart=on-failure
RestartSec=5
# iptables rules are managed by the daemon itself

[Install]
WantedBy=multi-user.target
`, targetPath, configPath)

	if err := os.WriteFile(serviceFile, []byte(serviceContent), 0644); err != nil {
		return fmt.Errorf("failed to write service file: %w", err)
	}

	// 3. Install CA certificate
	if err := installCA(); err != nil {
		return fmt.Errorf("failed to install CA: %w", err)
	}

	// 4. Add IPv6 route for fd00::/8 to localhost (for transport interception)
	fmt.Println("Adding IPv6 route for transport interception...")
	addRoute := exec.Command("ip", "-6", "route", "add", "fd00::/8", "dev", "lo")
	if err := addRoute.Run(); err != nil {
		// Route might already exist
		fmt.Printf("Warning: Failed to add IPv6 route (may already exist): %v\n", err)
	} else {
		fmt.Println("IPv6 route added for fd00::/8")
	}

	// 5. Enable and start service (iptables rules managed by daemon)
	if err := exec.Command("systemctl", "daemon-reload").Run(); err != nil {
		return fmt.Errorf("failed to reload systemd: %w", err)
	}
	if err := exec.Command("systemctl", "enable", serviceName).Run(); err != nil {
		return fmt.Errorf("failed to enable service: %w", err)
	}
	if err := exec.Command("systemctl", "start", serviceName).Run(); err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	fmt.Println("DNN Daemon installed successfully!")
	fmt.Println("Note: DNS interception via iptables (no system DNS modification)")

	return nil
}

// UninstallService stops and removes the systemd service
func UninstallService() error {
	// Stop and disable service
	exec.Command("systemctl", "stop", serviceName).Run()
	exec.Command("systemctl", "disable", serviceName).Run()

	// Remove service file
	os.Remove(serviceFile)
	exec.Command("systemctl", "daemon-reload").Run()

	// Remove IPv6 route
	fmt.Println("Removing IPv6 route...")
	exec.Command("ip", "-6", "route", "del", "fd00::/8", "dev", "lo").Run()

	// Remove CA
	uninstallCA()

	// Remove binary
	os.Remove("/usr/local/bin/dnn-daemon")

	fmt.Println("DNN Daemon uninstalled successfully!")
	fmt.Println("Note: iptables rules were managed by the daemon and removed on stop")

	return nil
}

// RunService runs the daemon (called with --service flag)
func RunService(cfg interface{}, debug bool) error {
	// On Linux, just run in foreground - systemd handles daemonization
	return fmt.Errorf("use foreground mode on Linux")
}

func installCA() error {
	caDir := "/etc/dnn"
	caCertPath := filepath.Join(caDir, "dnn-ca.crt")

	// Ensure CA directory exists
	if err := os.MkdirAll(caDir, 0755); err != nil {
		return err
	}

	// Generate CA if it doesn't exist
	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		// CA generation is handled by the certgen package
		// For now, just ensure the path exists
	}

	// Detect distro and install CA appropriately
	if isDebian() {
		// Debian/Ubuntu
		destPath := "/usr/local/share/ca-certificates/dnn-ca.crt"
		if _, err := os.Stat(caCertPath); err == nil {
			copyFile(caCertPath, destPath)
		}
		return exec.Command("update-ca-certificates").Run()
	} else if isRedHat() {
		// RHEL/Fedora
		destPath := "/etc/pki/ca-trust/source/anchors/dnn-ca.crt"
		if _, err := os.Stat(caCertPath); err == nil {
			copyFile(caCertPath, destPath)
		}
		return exec.Command("update-ca-trust").Run()
	}

	return nil
}

func uninstallCA() {
	// Remove from Debian path
	os.Remove("/usr/local/share/ca-certificates/dnn-ca.crt")
	exec.Command("update-ca-certificates", "--fresh").Run()

	// Remove from RHEL path
	os.Remove("/etc/pki/ca-trust/source/anchors/dnn-ca.crt")
	exec.Command("update-ca-trust").Run()
}

// Note: configureDNS and restoreDNS removed - iptables redirect is handled by capture module

func isDebian() bool {
	_, err := os.Stat("/etc/debian_version")
	return err == nil
}

func isRedHat() bool {
	_, err := os.Stat("/etc/redhat-release")
	return err == nil
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0644)
}

//go:build windows
// +build windows

package ca

import (
	"fmt"
	"os/exec"
	"strings"
)

const friendlyName = "DNN Network Certificate Authority"

// InstallToStore installs the CA certificate to the Windows certificate store
// This requires administrator privileges
func (ca *CA) InstallToStore() error {
	certPath := CertPath()

	// Use PowerShell to import the certificate with Friendly Name
	// This gives us more control than certutil
	psScript := fmt.Sprintf(`
$cert = Import-Certificate -FilePath "%s" -CertStoreLocation Cert:\LocalMachine\Root
$cert.FriendlyName = "%s"
`, certPath, friendlyName)

	cmd := exec.Command("powershell", "-NoProfile", "-Command", psScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		// Fallback to certutil if PowerShell fails
		cmd2 := exec.Command("certutil", "-addstore", "-f", "ROOT", certPath)
		output2, err2 := cmd2.CombinedOutput()
		if err2 != nil {
			return fmt.Errorf("failed to install CA to certificate store: %w\nPowerShell output: %s\ncertutil output: %s", err, string(output), string(output2))
		}
	}

	return nil
}

// RemoveFromStore removes the CA certificate from the Windows certificate store
func RemoveFromStore() error {
	// Use PowerShell to find and remove certificate by Friendly Name or Subject
	psScript := `
Get-ChildItem Cert:\LocalMachine\Root | Where-Object { 
    $_.FriendlyName -like "*DNN*" -or 
    $_.Subject -like "*DNN*" -or
    $_.Issuer -like "*DNN*"
} | Remove-Item -Force -ErrorAction SilentlyContinue
`
	cmd := exec.Command("powershell", "-NoProfile", "-Command", psScript)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to remove CA from store: %w\nOutput: %s", err, string(output))
	}

	return nil
}

// IsInstalledInStore checks if the CA is installed in the Windows certificate store
func IsInstalledInStore() bool {
	// Look for certificate with our friendly name or subject containing DNN
	psScript := `
$certs = Get-ChildItem Cert:\LocalMachine\Root | Where-Object { 
    $_.FriendlyName -eq "` + friendlyName + `" -or
    $_.Subject -like "*DNN Local CA*"
}
if ($certs.Count -gt 0) { exit 0 } else { exit 1 }
`
	cmd := exec.Command("powershell", "-NoProfile", "-Command", psScript)
	err := cmd.Run()
	return err == nil
}

// CleanupOldCerts removes any old DNN certificates that might be left over
func CleanupOldCerts() error {
	// Remove any certificates with DNN in the name
	psScript := `
Get-ChildItem Cert:\LocalMachine\Root | Where-Object { 
    $_.Subject -like "*DNN*" -or 
    $_.Issuer -like "*DNN*" -or
    $_.FriendlyName -like "*DNN*"
} | Remove-Item -Force -ErrorAction SilentlyContinue
`
	cmd := exec.Command("powershell", "-NoProfile", "-Command", strings.TrimSpace(psScript))
	_, _ = cmd.CombinedOutput() // Ignore errors, best effort cleanup
	return nil
}

//go:build windows
// +build windows

// Package dnsconfig handles automatic DNS configuration on Windows.
package dnsconfig

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// OriginalConfig stores the original DNS settings for restoration
type OriginalConfig struct {
	Interfaces []InterfaceConfig `json:"interfaces"`
}

// InterfaceConfig stores DNS config for a single interface
type InterfaceConfig struct {
	Name    string   `json:"name"`
	DNS     []string `json:"dns"`
	WasDHCP bool     `json:"was_dhcp"`
}

// ConfigPath returns the path to store original DNS config
func ConfigPath() string {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return filepath.Join(programData, "DNN", "original-dns.json")
}

// SetDNS configures Windows to use the local DNS server
// Sets only 127.0.0.1 (no fallback - dual DNS caused Windows to route some queries to fallback)
func SetDNS(localDNS string) error {
	// Get active network interfaces
	interfaces, err := getActiveInterfaces()
	if err != nil {
		return fmt.Errorf("failed to get interfaces: %w", err)
	}

	if len(interfaces) == 0 {
		return fmt.Errorf("no active network interfaces found")
	}

	// Load existing saved config (if any) and MERGE - don't overwrite
	existingConfig, _ := loadOriginalConfig()
	mergedInterfaces := mergeInterfaceConfigs(existingConfig, interfaces)

	// Save merged config
	mergedConfig := &OriginalConfig{Interfaces: mergedInterfaces}
	if err := saveOriginalConfig(mergedConfig); err != nil {
		return fmt.Errorf("failed to save original config: %w", err)
	}

	// Set single DNS for each currently active interface
	// NOTE: We don't use dual DNS because Windows sometimes routes queries to fallback
	// which returns NXDOMAIN for DNN names
	for _, iface := range interfaces {
		if err := setInterfaceDNS(iface.Name, localDNS); err != nil {
			fmt.Printf("Warning: Failed to set DNS for %s: %v\n", iface.Name, err)
		} else {
			fmt.Printf("Set DNS for %s: %s\n", iface.Name, localDNS)
		}
	}

	return nil
}

// RestoreDNS restores the original DNS configuration for ALL saved interfaces
// Works even for adapters that are currently disconnected
func RestoreDNS() error {
	config, err := loadOriginalConfig()
	if err != nil {
		// Even if config load fails, do brute-force cleanup
		fmt.Printf("Warning: Failed to load original config: %v\n", err)
		fmt.Println("Performing brute-force DNS cleanup...")
		return resetAllDaemonDNS()
	}

	// Get ALL adapters (not just active) so we can restore disconnected ones too
	allAdapters := getAllAdapterNames()

	// Restore ALL saved interfaces
	var lastErr error
	for _, iface := range config.Interfaces {
		// Check if adapter exists (even if disconnected)
		adapterExists := allAdapters[iface.Name]

		if !adapterExists {
			fmt.Printf("Adapter %s no longer exists, skipping\n", iface.Name)
			continue
		}

		if iface.WasDHCP {
			// Restore DHCP
			if err := setInterfaceDHCP(iface.Name); err != nil {
				fmt.Printf("Warning: Failed to restore DHCP for %s: %v\n", iface.Name, err)
				lastErr = err
			} else {
				fmt.Printf("Restored DHCP for %s\n", iface.Name)
			}
		} else if len(iface.DNS) > 0 {
			// Restore static DNS
			if err := setInterfaceDNS(iface.Name, iface.DNS[0]); err != nil {
				fmt.Printf("Warning: Failed to restore DNS for %s: %v\n", iface.Name, err)
				lastErr = err
			} else {
				fmt.Printf("Restored DNS for %s to %s\n", iface.Name, iface.DNS[0])
			}
		}
	}

	// BRUTE FORCE: Also scan ALL adapters for any with 127.0.0.1 and reset them
	// This catches any edge cases we might have missed
	fmt.Println("Scanning for any remaining adapters with daemon DNS...")
	if err := resetAllDaemonDNS(); err != nil {
		fmt.Printf("Warning: Brute force cleanup error: %v\n", err)
	}

	// Remove saved config
	os.Remove(ConfigPath())

	return lastErr
}

// resetAllDaemonDNS scans ALL adapters and resets any with 127.0.0.1 to DHCP
// Also resets WiFi network profiles that might have stored 127.0.0.1
func resetAllDaemonDNS() error {
	// PowerShell command to find and reset any adapter with 127.0.0.1 DNS
	// AND also reset the WiFi interface to DHCP for DNS
	cmd := exec.Command("powershell", "-NoProfile", "-Command", `
		# Reset all adapters with 127.0.0.1
		$adapters = Get-NetAdapter
		foreach ($adapter in $adapters) {
			$dns = Get-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
			if ($dns.ServerAddresses -contains "127.0.0.1") {
				Write-Host "Resetting DNS for adapter: $($adapter.Name)"
				Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ResetServerAddresses
			}
		}

		# Also use netsh to ensure WiFi DNS is reset (clears network profile settings)
		$wifiAdapter = Get-NetAdapter | Where-Object { $_.InterfaceDescription -like "*Wi-Fi*" -or $_.InterfaceDescription -like "*Wireless*" -or $_.Name -eq "Wi-Fi" }
		if ($wifiAdapter) {
			Write-Host "Resetting WiFi DNS via netsh for: $($wifiAdapter.Name)"
			netsh interface ipv4 set dnsservers name="$($wifiAdapter.Name)" source=dhcp 2>&1 | Out-Null
		}

		# Reset Ethernet too just in case
		$ethAdapter = Get-NetAdapter | Where-Object { $_.Name -eq "Ethernet" -or $_.InterfaceDescription -like "*Ethernet*" }
		if ($ethAdapter) {
			Write-Host "Resetting Ethernet DNS via netsh for: $($ethAdapter.Name)"
			netsh interface ipv4 set dnsservers name="$($ethAdapter.Name)" source=dhcp 2>&1 | Out-Null
		}
	`)

	output, err := cmd.CombinedOutput()
	if len(output) > 0 {
		fmt.Print(string(output))
	}
	return err
}

// getAllAdapterNames returns a map of ALL network adapter names (active and inactive)
func getAllAdapterNames() map[string]bool {
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		`Get-NetAdapter | ForEach-Object { $_.Name }`)

	output, err := cmd.Output()
	if err != nil {
		return make(map[string]bool)
	}

	names := make(map[string]bool)
	for _, line := range strings.Split(string(output), "\n") {
		name := strings.TrimSpace(line)
		if name != "" {
			names[name] = true
		}
	}

	return names
}

// mergeInterfaceConfigs merges new interfaces with existing saved config
// Keeps the ORIGINAL settings for interfaces we've already seen
func mergeInterfaceConfigs(existing *OriginalConfig, current []InterfaceConfig) []InterfaceConfig {
	if existing == nil || len(existing.Interfaces) == 0 {
		return current
	}

	// Build map of existing interfaces (keyed by name)
	existingMap := make(map[string]InterfaceConfig)
	for _, iface := range existing.Interfaces {
		existingMap[iface.Name] = iface
	}

	// For each current interface, only add it if we don't already have it saved
	for _, iface := range current {
		if _, exists := existingMap[iface.Name]; !exists {
			existingMap[iface.Name] = iface
		}
		// If it exists, keep the ORIGINAL saved settings (don't overwrite with 127.0.0.1)
	}

	// Convert map back to slice
	var result []InterfaceConfig
	for _, iface := range existingMap {
		result = append(result, iface)
	}

	return result
}

// getActiveInterfaces returns active network interfaces with their current DNS
func getActiveInterfaces() ([]InterfaceConfig, error) {
	// Use PowerShell to get interface info
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		`Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | ForEach-Object {
			$dns = Get-DnsClientServerAddress -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
			$config = Get-NetIPInterface -InterfaceIndex $_.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue
			[PSCustomObject]@{
				Name = $_.Name
				DNS = ($dns.ServerAddresses -join ",")
				DHCP = $config.Dhcp -eq 'Enabled'
			}
		} | ConvertTo-Json -Compress`)

	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	// Parse JSON output
	var interfaces []struct {
		Name string `json:"Name"`
		DNS  string `json:"DNS"`
		DHCP bool   `json:"DHCP"`
	}

	// Handle single object vs array
	outputStr := strings.TrimSpace(string(output))
	if outputStr == "" {
		return nil, nil
	}

	if outputStr[0] == '[' {
		if err := json.Unmarshal(output, &interfaces); err != nil {
			return nil, fmt.Errorf("failed to parse interface list: %w", err)
		}
	} else {
		var single struct {
			Name string `json:"Name"`
			DNS  string `json:"DNS"`
			DHCP bool   `json:"DHCP"`
		}
		if err := json.Unmarshal(output, &single); err != nil {
			return nil, fmt.Errorf("failed to parse interface: %w", err)
		}
		interfaces = append(interfaces, single)
	}

	var result []InterfaceConfig
	for _, iface := range interfaces {
		var dnsServers []string
		if iface.DNS != "" {
			dnsServers = strings.Split(iface.DNS, ",")
		}
		result = append(result, InterfaceConfig{
			Name:    iface.Name,
			DNS:     dnsServers,
			WasDHCP: iface.DHCP,
		})
	}

	return result, nil
}

// setInterfaceDNS sets a static DNS server for an interface
func setInterfaceDNS(interfaceName, dnsServer string) error {
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		fmt.Sprintf(`Set-DnsClientServerAddress -InterfaceAlias "%s" -ServerAddresses "%s"`,
			interfaceName, dnsServer))
	return cmd.Run()
}

// setInterfaceDualDNS sets two DNS servers for an interface (primary + fallback)
func setInterfaceDualDNS(interfaceName, primary, fallback string) error {
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		fmt.Sprintf(`Set-DnsClientServerAddress -InterfaceAlias "%s" -ServerAddresses "%s","%s"`,
			interfaceName, primary, fallback))
	return cmd.Run()
}

// setInterfaceDHCP restores DHCP for an interface
func setInterfaceDHCP(interfaceName string) error {
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		fmt.Sprintf(`Set-DnsClientServerAddress -InterfaceAlias "%s" -ResetServerAddresses`,
			interfaceName))
	return cmd.Run()
}

// getDefaultGateway gets the default gateway for an interface (usually the router)
func getDefaultGateway(interfaceName string) string {
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		fmt.Sprintf(`(Get-NetIPConfiguration -InterfaceAlias "%s").IPv4DefaultGateway.NextHop`,
			interfaceName))
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(output))
}

// saveOriginalConfig saves the original DNS config to disk
func saveOriginalConfig(config *OriginalConfig) error {
	// Ensure directory exists
	dir := filepath.Dir(ConfigPath())
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(ConfigPath(), data, 0644)
}

// loadOriginalConfig loads the saved original DNS config
func loadOriginalConfig() (*OriginalConfig, error) {
	data, err := os.ReadFile(ConfigPath())
	if err != nil {
		return nil, err
	}

	var config OriginalConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	return &config, nil
}

// HasSavedConfig checks if there's a saved original config
func HasSavedConfig() bool {
	_, err := os.Stat(ConfigPath())
	return err == nil
}

// GetOriginalUpstreams returns the original DNS servers saved at install time
// This is kept for restoration purposes
func GetOriginalUpstreams() []string {
	config, err := loadOriginalConfig()
	if err != nil {
		return getDefaultUpstreams()
	}

	seen := make(map[string]bool)
	var upstreams []string

	for _, iface := range config.Interfaces {
		for _, dns := range iface.DNS {
			dns = strings.TrimSpace(dns)
			if dns != "" && dns != "127.0.0.1" && !seen[dns] {
				seen[dns] = true
				upstreams = append(upstreams, dns+":53")
			}
		}
	}

	if len(upstreams) > 0 {
		return upstreams
	}
	return getDefaultUpstreams()
}

// GetCurrentUpstreams returns the CURRENT network's DNS servers
// This queries DHCP live, so it works when roaming between networks
func GetCurrentUpstreams() []string {
	// Query current DHCP-provided DNS servers from all active interfaces
	cmd := exec.Command("powershell", "-NoProfile", "-Command",
		`Get-DnsClientServerAddress -AddressFamily IPv4 | 
		Where-Object { $_.ServerAddresses -ne $null -and $_.ServerAddresses.Count -gt 0 } | 
		ForEach-Object { $_.ServerAddresses } | 
		Where-Object { $_ -ne "127.0.0.1" } | 
		Select-Object -Unique`)

	output, err := cmd.Output()
	if err != nil {
		return getDefaultUpstreams()
	}

	var upstreams []string
	for _, line := range strings.Split(string(output), "\n") {
		dns := strings.TrimSpace(line)
		if dns != "" && dns != "127.0.0.1" {
			upstreams = append(upstreams, dns+":53")
		}
	}

	if len(upstreams) > 0 {
		return upstreams
	}

	return getDefaultUpstreams()
}

// getDefaultUpstreams returns default DNS servers when nothing else works
func getDefaultUpstreams() []string {
	// Using Cloudflare and Quad9 as they're fast and privacy-focused
	return []string{"1.1.1.1:53", "9.9.9.9:53"}
}

// EnsureDNS checks if all active interfaces have DNS set to localDNS
// If not, it configures them (used for auto-healing when switching networks)
// Returns true if any changes were made
func EnsureDNS(localDNS string) (changed bool, err error) {
	interfaces, err := getActiveInterfaces()
	if err != nil {
		return false, err
	}

	for _, iface := range interfaces {
		needsConfig := true
		for _, dns := range iface.DNS {
			if dns == localDNS {
				needsConfig = false
				break
			}
		}

		if needsConfig {
			// This interface doesn't have our DNS - save its original config and configure
			existingConfig, _ := loadOriginalConfig()
			mergedInterfaces := mergeInterfaceConfigs(existingConfig, []InterfaceConfig{iface})
			mergedConfig := &OriginalConfig{Interfaces: mergedInterfaces}
			_ = saveOriginalConfig(mergedConfig) // Best effort save

			if err := setInterfaceDNS(iface.Name, localDNS); err == nil {
				changed = true
			}
		}
	}

	return changed, nil
}

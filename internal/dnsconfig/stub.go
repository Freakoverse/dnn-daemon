//go:build !windows
// +build !windows

// Package dnsconfig handles automatic DNS configuration.
// This is the stub for non-Windows platforms.
package dnsconfig

import "errors"

// SetDNS configures the system to use the local DNS server
func SetDNS(localDNS string) error {
	return errors.New("automatic DNS configuration not implemented for this platform")
}

// RestoreDNS restores the original DNS configuration
func RestoreDNS() error {
	return errors.New("automatic DNS restoration not implemented for this platform")
}

// HasSavedConfig checks if there's a saved original config
func HasSavedConfig() bool {
	return false
}

// ConfigPath returns the path to store original DNS config
func ConfigPath() string {
	return "/etc/dnn/original-dns.json"
}

// GetOriginalUpstreams returns saved DNS (for restoration)
func GetOriginalUpstreams() []string {
	return []string{"1.1.1.1:53", "9.9.9.9:53"}
}

// GetCurrentUpstreams returns the CURRENT network's DNS servers
// On Linux, this would parse /etc/resolv.conf
func GetCurrentUpstreams() []string {
	// TODO: Parse /etc/resolv.conf for current nameservers
	// For now, use Cloudflare and Quad9 as fallbacks
	return []string{"1.1.1.1:53", "9.9.9.9:53"}
}

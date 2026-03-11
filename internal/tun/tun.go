// Package tun provides a cross-platform TUN interface for the DNN daemon.
//
// On Windows, it uses WinTUN (wintun.dll) from the WireGuard project.
// On Linux, it uses the native /dev/net/tun interface.
// On macOS, it uses the utun interface.
package tun

import (
	"errors"
	"io"
	"net"
)

// ErrClosed is returned when operating on a closed TUN device
var ErrClosed = errors.New("tun device is closed")

// Device represents a TUN network interface
type Device interface {
	// Name returns the interface name (e.g., "DNN", "tun0", "utun3")
	Name() string

	// Read reads a single packet from the TUN interface
	// The packet is an IP packet (no ethernet header)
	Read(buf []byte) (n int, err error)

	// Write writes a single packet to the TUN interface
	Write(buf []byte) (n int, err error)

	// MTU returns the Maximum Transmission Unit of the interface
	MTU() int

	// Close closes the TUN device
	Close() error
}

// Config holds configuration for creating a TUN device
type Config struct {
	// Name is the desired interface name (may be overridden by OS)
	Name string

	// MTU is the Maximum Transmission Unit (default: 1420)
	MTU int

	// Address is the IPv4 address to assign (e.g., "10.0.85.1/24")
	Address *net.IPNet

	// Address6 is the IPv6 address to assign (e.g., "fd00::1/8")
	Address6 *net.IPNet
}

// DefaultConfig returns a default TUN configuration for DNN
func DefaultConfig() *Config {
	// ParseCIDR returns (hostIP, network, err)
	// We need the host IP (10.0.85.1), not the network (10.0.85.0)
	ipv4, ipv4Net, _ := net.ParseCIDR("10.0.85.1/24")
	ipv6, ipv6Net, _ := net.ParseCIDR("fd00::1/8")

	// Set the host IP in the IPNet
	ipv4Net.IP = ipv4
	ipv6Net.IP = ipv6

	return &Config{
		Name:     "DNN",
		MTU:      1420,
		Address:  ipv4Net,
		Address6: ipv6Net,
	}
}

// New creates a new TUN device with the given configuration.
// This is platform-specific and implemented in tun_*.go files.
func New(cfg *Config) (Device, error) {
	if cfg == nil {
		cfg = DefaultConfig()
	}
	return newTUN(cfg)
}

// Ensure io.ReadWriteCloser compatibility
var _ io.ReadWriteCloser = (Device)(nil)

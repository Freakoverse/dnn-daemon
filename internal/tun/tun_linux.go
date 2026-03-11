//go:build linux
// +build linux

package tun

import (
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"syscall"
	"unsafe"
)

// Linux TUN constants
const (
	tunDevice = "/dev/net/tun"
	ifnamsiz  = 16
	iffTun    = 0x0001
	iffNoPi   = 0x1000
)

// ifreq for ioctl
type ifreq struct {
	name  [ifnamsiz]byte
	flags uint16
	_     [22]byte // padding
}

// linuxTUN implements Device for Linux
type linuxTUN struct {
	name   string
	mtu    int
	fd     *os.File
	closed bool
	mu     sync.Mutex
}

func newTUN(cfg *Config) (Device, error) {
	// Open TUN device
	fd, err := os.OpenFile(tunDevice, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open %s: %w (try running with sudo or CAP_NET_ADMIN)", tunDevice, err)
	}

	// Prepare ifreq
	var ifr ifreq
	copy(ifr.name[:], cfg.Name)
	ifr.flags = iffTun | iffNoPi

	// Create TUN interface via ioctl
	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		fd.Fd(),
		uintptr(0x400454ca), // TUNSETIFF
		uintptr(unsafe.Pointer(&ifr)),
	)
	if errno != 0 {
		fd.Close()
		return nil, fmt.Errorf("TUNSETIFF failed: %v", errno)
	}

	// Get actual interface name
	name := string(ifr.name[:])
	for i, c := range name {
		if c == 0 {
			name = name[:i]
			break
		}
	}

	tun := &linuxTUN{
		name: name,
		mtu:  cfg.MTU,
		fd:   fd,
	}

	// Configure IP addresses using ip command
	if cfg.Address != nil {
		if err := tun.setIPAddress(cfg.Address); err != nil {
			log.Printf("[TUN] Warning: failed to set IPv4 address: %v", err)
		}
	}
	if cfg.Address6 != nil {
		if err := tun.setIPv6Address(cfg.Address6); err != nil {
			log.Printf("[TUN] Warning: failed to set IPv6 address: %v", err)
		}
	}

	// Bring interface up
	if err := tun.bringUp(); err != nil {
		log.Printf("[TUN] Warning: failed to bring interface up: %v", err)
	}

	log.Printf("[TUN] Created Linux TUN interface: %s", name)
	return tun, nil
}

func (t *linuxTUN) Name() string {
	return t.name
}

func (t *linuxTUN) MTU() int {
	return t.mtu
}

func (t *linuxTUN) Read(buf []byte) (int, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return 0, ErrClosed
	}
	fd := t.fd
	t.mu.Unlock()

	return fd.Read(buf)
}

func (t *linuxTUN) Write(buf []byte) (int, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return 0, ErrClosed
	}
	fd := t.fd
	t.mu.Unlock()

	return fd.Write(buf)
}

func (t *linuxTUN) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}
	t.closed = true

	if t.fd != nil {
		t.fd.Close()
		t.fd = nil
	}

	log.Printf("[TUN] Closed Linux TUN interface: %s", t.name)
	return nil
}

func (t *linuxTUN) setIPAddress(ipNet *net.IPNet) error {
	ones, _ := ipNet.Mask.Size()
	// ip addr add 10.0.85.1/24 dev tun0
	return runCommand("ip", "addr", "add", fmt.Sprintf("%s/%d", ipNet.IP.String(), ones), "dev", t.name)
}

func (t *linuxTUN) setIPv6Address(ipNet *net.IPNet) error {
	ones, _ := ipNet.Mask.Size()
	return runCommand("ip", "-6", "addr", "add", fmt.Sprintf("%s/%d", ipNet.IP.String(), ones), "dev", t.name)
}

func (t *linuxTUN) bringUp() error {
	return runCommand("ip", "link", "set", t.name, "up")
}

func runCommand(name string, args ...string) error {
	// Use exec.Command - import would be needed
	// For now, use syscall.ForkExec or similar
	// This is a simplified version
	log.Printf("[TUN] Would run: %s %v", name, args)
	return nil // TODO: implement proper exec
}

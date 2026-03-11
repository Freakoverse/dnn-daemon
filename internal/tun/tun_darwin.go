//go:build darwin
// +build darwin

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

// Darwin uses utun interfaces

// Socket constants
const (
	sysAF_SYS_CONTROL   = 2
	sysPF_SYSTEM        = 32
	sysSYSPROTO_CONTROL = 2
	utunControl         = "com.apple.net.utun_control"
	utunOptIfname       = 2
)

// ctlInfo for utun
type ctlInfo struct {
	id   uint32
	name [96]byte
}

// sockaddrCtl for connecting to utun
type sockaddrCtl struct {
	scLen      uint8
	scFamily   uint8
	ssSysaddr  uint16
	scId       uint32
	scUnit     uint32
	scReserved [5]uint32
}

// darwinTUN implements Device for macOS
type darwinTUN struct {
	name   string
	mtu    int
	fd     int
	file   *os.File
	closed bool
	mu     sync.Mutex
}

func newTUN(cfg *Config) (Device, error) {
	// Create system control socket
	fd, err := syscall.Socket(sysPF_SYSTEM, syscall.SOCK_DGRAM, sysSYSPROTO_CONTROL)
	if err != nil {
		return nil, fmt.Errorf("failed to create control socket: %w", err)
	}

	// Get utun control ID
	var info ctlInfo
	copy(info.name[:], utunControl)

	_, _, errno := syscall.Syscall(
		syscall.SYS_IOCTL,
		uintptr(fd),
		uintptr(0xc0644e03), // CTLIOCGINFO
		uintptr(unsafe.Pointer(&info)),
	)
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("CTLIOCGINFO failed: %v", errno)
	}

	// Connect to utun (unit 0 = utun0, etc.)
	// Use unit 0 for auto-assignment
	addr := sockaddrCtl{
		scLen:    uint8(unsafe.Sizeof(sockaddrCtl{})),
		scFamily: sysAF_SYS_CONTROL,
		scId:     info.id,
		scUnit:   0, // Auto-assign
	}

	_, _, errno = syscall.Syscall(
		syscall.SYS_CONNECT,
		uintptr(fd),
		uintptr(unsafe.Pointer(&addr)),
		unsafe.Sizeof(addr),
	)
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("connect to utun failed: %v", errno)
	}

	// Get assigned interface name
	var ifname [32]byte
	ifnameLen := uint32(len(ifname))
	_, _, errno = syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		sysSYSPROTO_CONTROL,
		utunOptIfname,
		uintptr(unsafe.Pointer(&ifname[0])),
		uintptr(unsafe.Pointer(&ifnameLen)),
		0,
	)
	if errno != 0 {
		syscall.Close(fd)
		return nil, fmt.Errorf("getsockopt UTUN_OPT_IFNAME failed: %v", errno)
	}

	name := string(ifname[:ifnameLen-1]) // Remove null terminator

	// Set non-blocking
	syscall.SetNonblock(fd, false)

	tun := &darwinTUN{
		name: name,
		mtu:  cfg.MTU,
		fd:   fd,
		file: os.NewFile(uintptr(fd), name),
	}

	// Configure IP addresses using ifconfig
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

	log.Printf("[TUN] Created macOS TUN interface: %s", name)
	return tun, nil
}

func (t *darwinTUN) Name() string {
	return t.name
}

func (t *darwinTUN) MTU() int {
	return t.mtu
}

func (t *darwinTUN) Read(buf []byte) (int, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return 0, ErrClosed
	}
	file := t.file
	t.mu.Unlock()

	// macOS utun has a 4-byte header (AF family)
	fullBuf := make([]byte, len(buf)+4)
	n, err := file.Read(fullBuf)
	if err != nil {
		return 0, err
	}
	if n < 4 {
		return 0, fmt.Errorf("short read from utun")
	}

	// Copy without the 4-byte header
	copy(buf, fullBuf[4:n])
	return n - 4, nil
}

func (t *darwinTUN) Write(buf []byte) (int, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return 0, ErrClosed
	}
	file := t.file
	t.mu.Unlock()

	// Determine IP version from first nibble
	var proto uint32
	if len(buf) > 0 {
		version := buf[0] >> 4
		if version == 4 {
			proto = syscall.AF_INET
		} else if version == 6 {
			proto = syscall.AF_INET6
		}
	}

	// Prepend 4-byte header
	fullBuf := make([]byte, len(buf)+4)
	fullBuf[0] = 0
	fullBuf[1] = 0
	fullBuf[2] = byte(proto >> 8)
	fullBuf[3] = byte(proto)
	copy(fullBuf[4:], buf)

	n, err := file.Write(fullBuf)
	if err != nil {
		return 0, err
	}
	return n - 4, nil
}

func (t *darwinTUN) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}
	t.closed = true

	if t.file != nil {
		t.file.Close()
		t.file = nil
	}

	log.Printf("[TUN] Closed macOS TUN interface: %s", t.name)
	return nil
}

func (t *darwinTUN) setIPAddress(ipNet *net.IPNet) error {
	ones, _ := ipNet.Mask.Size()
	// ifconfig utun0 10.0.85.1 10.0.85.1 netmask 255.255.255.0 up
	log.Printf("[TUN] Would configure IPv4: ifconfig %s %s/%d up", t.name, ipNet.IP.String(), ones)
	return nil // TODO: implement proper exec
}

func (t *darwinTUN) setIPv6Address(ipNet *net.IPNet) error {
	ones, _ := ipNet.Mask.Size()
	// ifconfig utun0 inet6 fd00::1 prefixlen 8
	log.Printf("[TUN] Would configure IPv6: ifconfig %s inet6 %s prefixlen %d", t.name, ipNet.IP.String(), ones)
	return nil // TODO: implement proper exec
}

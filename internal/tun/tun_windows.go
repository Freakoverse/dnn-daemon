//go:build windows
// +build windows

package tun

import (
	"fmt"
	"log"
	"net"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WinTUN DLL exports
var (
	wintunDLL                  *windows.DLL
	wintunCreateAdapter        *windows.Proc
	wintunCloseAdapter         *windows.Proc
	wintunStartSession         *windows.Proc
	wintunEndSession           *windows.Proc
	wintunGetReadWaitEvent     *windows.Proc
	wintunReceivePacket        *windows.Proc
	wintunReleaseReceivePacket *windows.Proc
	wintunAllocateSendPacket   *windows.Proc
	wintunSendPacket           *windows.Proc
	wintunGetAdapterLUID       *windows.Proc
	wintunSetAdapterAddresses  *windows.Proc
)

// GUID for DNN adapter (fixed for consistency)
var dnnGUID = windows.GUID{
	Data1: 0x12345678,
	Data2: 0x1234,
	Data3: 0x1234,
	Data4: [8]byte{0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0},
}

func init() {
	// Try to load wintun.dll from current directory, then system path
	var err error
	wintunDLL, err = windows.LoadDLL("wintun.dll")
	if err != nil {
		// Try loading from executable directory
		log.Printf("[TUN] Warning: wintun.dll not found in PATH, will fail on first use: %v", err)
		return
	}

	// Load all required procedures
	wintunCreateAdapter, _ = wintunDLL.FindProc("WintunCreateAdapter")
	wintunCloseAdapter, _ = wintunDLL.FindProc("WintunCloseAdapter")
	wintunStartSession, _ = wintunDLL.FindProc("WintunStartSession")
	wintunEndSession, _ = wintunDLL.FindProc("WintunEndSession")
	wintunGetReadWaitEvent, _ = wintunDLL.FindProc("WintunGetReadWaitEvent")
	wintunReceivePacket, _ = wintunDLL.FindProc("WintunReceivePacket")
	wintunReleaseReceivePacket, _ = wintunDLL.FindProc("WintunReleaseReceivePacket")
	wintunAllocateSendPacket, _ = wintunDLL.FindProc("WintunAllocateSendPacket")
	wintunSendPacket, _ = wintunDLL.FindProc("WintunSendPacket")
	wintunGetAdapterLUID, _ = wintunDLL.FindProc("WintunGetAdapterLUID")
}

// windowsTUN implements Device for Windows using WinTUN
type windowsTUN struct {
	name      string
	mtu       int
	adapter   uintptr
	session   uintptr
	readEvent windows.Handle
	closed    bool
	mu        sync.Mutex
}

func newTUN(cfg *Config) (Device, error) {
	if wintunDLL == nil {
		return nil, fmt.Errorf("wintun.dll not loaded - ensure it's in the same directory as the daemon")
	}

	// Convert name to wide string
	namePtr, err := windows.UTF16PtrFromString(cfg.Name)
	if err != nil {
		return nil, fmt.Errorf("invalid adapter name: %w", err)
	}

	// Create the adapter
	// WintunCreateAdapter(Name, TunnelType, RequestedGUID) -> Adapter
	tunnelType, _ := windows.UTF16PtrFromString("DNN")
	ret, _, err := wintunCreateAdapter.Call(
		uintptr(unsafe.Pointer(namePtr)),
		uintptr(unsafe.Pointer(tunnelType)),
		uintptr(unsafe.Pointer(&dnnGUID)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("WintunCreateAdapter failed: %w", err)
	}
	adapter := ret

	// Start a session with capacity for packets
	// Capacity must be between 0x20000 (128KB) and 0x4000000 (64MB), and power of 2
	const ringCapacity = 0x400000 // 4MB
	ret, _, err = wintunStartSession.Call(adapter, ringCapacity)
	if ret == 0 {
		wintunCloseAdapter.Call(adapter)
		return nil, fmt.Errorf("WintunStartSession failed: %w", err)
	}
	session := ret

	// Get the read wait event
	ret, _, _ = wintunGetReadWaitEvent.Call(session)
	if ret == 0 {
		wintunEndSession.Call(session)
		wintunCloseAdapter.Call(adapter)
		return nil, fmt.Errorf("WintunGetReadWaitEvent failed")
	}
	readEvent := windows.Handle(ret)

	tun := &windowsTUN{
		name:      cfg.Name,
		mtu:       cfg.MTU,
		adapter:   adapter,
		session:   session,
		readEvent: readEvent,
	}

	// Configure IP addresses using netsh
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

	// Set up DNS routing - route common DNS servers through TUN
	// This ensures we intercept all DNS queries before they leave the system
	if err := tun.setupDNSRouting(); err != nil {
		log.Printf("[TUN] Warning: failed to set up DNS routing: %v", err)
	}

	log.Printf("[TUN] Created Windows TUN adapter: %s", cfg.Name)
	return tun, nil
}

func (t *windowsTUN) Name() string {
	return t.name
}

func (t *windowsTUN) MTU() int {
	return t.mtu
}

func (t *windowsTUN) Read(buf []byte) (int, error) {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return 0, ErrClosed
	}
	t.mu.Unlock()

	for {
		// Wait for packet
		windows.WaitForSingleObject(t.readEvent, windows.INFINITE)

		t.mu.Lock()
		if t.closed {
			t.mu.Unlock()
			return 0, ErrClosed
		}

		// Try to receive a packet
		var packetSize uint32
		ret, _, _ := wintunReceivePacket.Call(
			t.session,
			uintptr(unsafe.Pointer(&packetSize)),
		)
		if ret == 0 {
			t.mu.Unlock()
			continue // No packet available, wait again
		}

		// Copy packet data
		packetPtr := ret
		n := int(packetSize)
		if n > len(buf) {
			n = len(buf)
		}

		// Copy from WinTUN buffer to our buffer
		src := unsafe.Slice((*byte)(unsafe.Pointer(packetPtr)), packetSize)
		copy(buf[:n], src)

		// Release the packet
		wintunReleaseReceivePacket.Call(t.session, packetPtr)
		t.mu.Unlock()

		return n, nil
	}
}

func (t *windowsTUN) Write(buf []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return 0, ErrClosed
	}

	packetSize := uint32(len(buf))

	// Allocate send packet
	ret, _, err := wintunAllocateSendPacket.Call(
		t.session,
		uintptr(packetSize),
	)
	if ret == 0 {
		return 0, fmt.Errorf("WintunAllocateSendPacket failed: %w", err)
	}

	// Copy data to packet
	dst := unsafe.Slice((*byte)(unsafe.Pointer(ret)), packetSize)
	copy(dst, buf)

	// Send the packet
	wintunSendPacket.Call(t.session, ret)

	return len(buf), nil
}

func (t *windowsTUN) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return nil
	}
	t.closed = true

	// End session
	if t.session != 0 {
		wintunEndSession.Call(t.session)
		t.session = 0
	}

	// Close adapter
	if t.adapter != 0 {
		wintunCloseAdapter.Call(t.adapter)
		t.adapter = 0
	}

	log.Printf("[TUN] Closed Windows TUN adapter: %s", t.name)
	return nil
}

// setIPAddress configures the IPv4 address using netsh
func (t *windowsTUN) setIPAddress(ipNet *net.IPNet) error {
	// Use netsh to set IP address
	// netsh interface ip set address "DNN" static 10.0.85.1 255.255.255.0
	ones, _ := ipNet.Mask.Size()
	mask := net.CIDRMask(ones, 32)
	maskStr := fmt.Sprintf("%d.%d.%d.%d", mask[0], mask[1], mask[2], mask[3])

	cmd := fmt.Sprintf(`netsh interface ip set address "%s" static %s %s`, t.name, ipNet.IP.String(), maskStr)
	log.Printf("[TUN] Configuring IPv4: %s", cmd)

	// Execute netsh via CreateProcess
	return runNetshCommand("interface", "ip", "set", "address", t.name, "static", ipNet.IP.String(), maskStr)
}

// setIPv6Address configures the IPv6 address using netsh
func (t *windowsTUN) setIPv6Address(ipNet *net.IPNet) error {
	ones, _ := ipNet.Mask.Size()
	cmd := fmt.Sprintf(`netsh interface ipv6 add address "%s" %s/%d`, t.name, ipNet.IP.String(), ones)
	log.Printf("[TUN] Configuring IPv6: %s", cmd)

	return runNetshCommand("interface", "ipv6", "add", "address", t.name, fmt.Sprintf("%s/%d", ipNet.IP.String(), ones))
}

// runNetshCommand executes a netsh command
func runNetshCommand(args ...string) error {
	// Build command line with proper quoting for arguments with spaces
	cmdLine := "cmd.exe /C netsh"
	for _, arg := range args {
		// Quote arguments that might contain spaces
		if len(arg) > 0 && (arg[0] != '"') {
			cmdLine += ` "` + arg + `"`
		} else {
			cmdLine += " " + arg
		}
	}
	cmdLinePtr, _ := windows.UTF16PtrFromString(cmdLine)

	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))

	// Use nil for lpApplicationName to let Windows search PATH for cmd.exe
	err := windows.CreateProcess(
		nil,
		cmdLinePtr,
		nil,
		nil,
		false,
		windows.CREATE_NO_WINDOW,
		nil,
		nil,
		&si,
		&pi,
	)
	if err != nil {
		return fmt.Errorf("CreateProcess failed: %w", err)
	}

	// Wait for completion
	windows.WaitForSingleObject(pi.Process, windows.INFINITE)
	windows.CloseHandle(pi.Process)
	windows.CloseHandle(pi.Thread)

	return nil
}

// runRouteCommand executes a route command
func runRouteCommand(args ...string) error {
	cmdLine := "cmd.exe /C route"
	for _, arg := range args {
		cmdLine += " " + arg
	}
	cmdLinePtr, _ := windows.UTF16PtrFromString(cmdLine)

	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))

	err := windows.CreateProcess(
		nil,
		cmdLinePtr,
		nil,
		nil,
		false,
		windows.CREATE_NO_WINDOW,
		nil,
		nil,
		&si,
		&pi,
	)
	if err != nil {
		return fmt.Errorf("CreateProcess failed: %w", err)
	}

	windows.WaitForSingleObject(pi.Process, windows.INFINITE)
	windows.CloseHandle(pi.Process)
	windows.CloseHandle(pi.Thread)

	return nil
}

// setupDNSRouting sets up routing to intercept DNS traffic through the TUN interface
// This routes DNS servers (both common and system-configured) through our TUN
func (t *windowsTUN) setupDNSRouting() error {
	// Get the interface index for our TUN adapter
	ifIndex := getInterfaceIndex(t.name)
	if ifIndex == "" {
		log.Printf("[TUN] Warning: could not determine interface index for %s", t.name)
		return nil
	}
	log.Printf("[TUN] TUN interface index: %s", ifIndex)

	// Common public DNS servers to intercept
	dnsServers := []string{
		"8.8.8.8",         // Google DNS
		"8.8.4.4",         // Google DNS
		"1.1.1.1",         // Cloudflare DNS
		"1.0.0.1",         // Cloudflare DNS
		"9.9.9.9",         // Quad9 DNS
		"149.112.112.112", // Quad9 DNS
		"208.67.222.222",  // OpenDNS
		"208.67.220.220",  // OpenDNS
	}

	// Detect system DNS servers and add them too (but skip local network addresses)
	systemDNS := getSystemDNSServers()
	for _, dns := range systemDNS {
		// Skip local network addresses - routing these through TUN causes loops
		// because we'd intercept, try to forward, and get the packet back
		if isLocalNetworkIP(dns) {
			log.Printf("[TUN] Skipping local DNS server (direct access): %s", dns)
			continue
		}

		// Avoid duplicates
		found := false
		for _, existing := range dnsServers {
			if existing == dns {
				found = true
				break
			}
		}
		if !found {
			dnsServers = append(dnsServers, dns)
		}
	}

	log.Printf("[TUN] Setting up DNS routing through TUN interface")
	log.Printf("[TUN] System DNS servers detected: %v", systemDNS)

	for _, dns := range dnsServers {
		// Add route with explicit interface: route ADD <dns> MASK 255.255.255.255 0.0.0.0 IF <index>
		// Using 0.0.0.0 as gateway with IF tells Windows to send directly via that interface
		err := runRouteCommand("ADD", dns, "MASK", "255.255.255.255", "0.0.0.0", "IF", ifIndex)
		if err != nil {
			log.Printf("[TUN] Warning: failed to add route for %s: %v", dns, err)
		} else {
			log.Printf("[TUN] Added route: %s -> TUN (IF %s)", dns, ifIndex)
		}
	}

	// Also route fd00::/8 for IPv6 DNN transports
	// This is handled separately via IPv6 routes

	return nil
}

// getInterfaceIndex gets the Windows interface index for the named adapter
func getInterfaceIndex(name string) string {
	cmdLine := "cmd.exe /C netsh interface ipv4 show interfaces"
	cmdLinePtr, _ := windows.UTF16PtrFromString(cmdLine)

	var stdoutRead, stdoutWrite windows.Handle
	var sa windows.SecurityAttributes
	sa.Length = uint32(unsafe.Sizeof(sa))
	sa.InheritHandle = 1

	if err := windows.CreatePipe(&stdoutRead, &stdoutWrite, &sa, 0); err != nil {
		return ""
	}
	defer windows.CloseHandle(stdoutRead)

	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = windows.STARTF_USESTDHANDLES
	si.StdOutput = stdoutWrite
	si.StdErr = stdoutWrite

	err := windows.CreateProcess(nil, cmdLinePtr, nil, nil, true, windows.CREATE_NO_WINDOW, nil, nil, &si, &pi)
	if err != nil {
		windows.CloseHandle(stdoutWrite)
		return ""
	}

	windows.CloseHandle(stdoutWrite)
	windows.WaitForSingleObject(pi.Process, windows.INFINITE)
	windows.CloseHandle(pi.Process)
	windows.CloseHandle(pi.Thread)

	output := make([]byte, 65536)
	var bytesRead uint32
	windows.ReadFile(stdoutRead, output, &bytesRead, nil)

	// Parse output to find interface index for our adapter name
	lines := splitLines(string(output[:bytesRead]))
	for _, line := range lines {
		if containsString(line, name) {
			// Line format: "  50           5       65535  connected     DNN"
			// Extract the first number (index)
			fields := splitFields(line)
			if len(fields) >= 1 {
				return fields[0]
			}
		}
	}

	return ""
}

// splitFields splits a string by whitespace
func splitFields(s string) []string {
	var fields []string
	inField := false
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ' ' || s[i] == '\t' {
			if inField {
				fields = append(fields, s[start:i])
				inField = false
			}
		} else {
			if !inField {
				start = i
				inField = true
			}
		}
	}
	if inField {
		fields = append(fields, s[start:])
	}
	return fields
}

// cleanupDNSRouting removes the DNS routing rules
func (t *windowsTUN) cleanupDNSRouting() {
	dnsServers := []string{
		"8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
		"9.9.9.9", "149.112.112.112", "208.67.222.222", "208.67.220.220",
	}

	for _, dns := range dnsServers {
		runRouteCommand("DELETE", dns)
	}
	log.Printf("[TUN] Cleaned up DNS routes")
}

// getSystemDNSServers detects the system's configured DNS servers
func getSystemDNSServers() []string {
	var servers []string

	// Run ipconfig /all and parse DNS Servers lines
	cmdLine := "cmd.exe /C ipconfig /all"
	cmdLinePtr, _ := windows.UTF16PtrFromString(cmdLine)

	// Create pipe for output
	var stdoutRead, stdoutWrite windows.Handle
	var sa windows.SecurityAttributes
	sa.Length = uint32(unsafe.Sizeof(sa))
	sa.InheritHandle = 1

	if err := windows.CreatePipe(&stdoutRead, &stdoutWrite, &sa, 0); err != nil {
		log.Printf("[TUN] Failed to create pipe: %v", err)
		return servers
	}
	defer windows.CloseHandle(stdoutRead)

	var si windows.StartupInfo
	var pi windows.ProcessInformation
	si.Cb = uint32(unsafe.Sizeof(si))
	si.Flags = windows.STARTF_USESTDHANDLES
	si.StdOutput = stdoutWrite
	si.StdErr = stdoutWrite

	err := windows.CreateProcess(
		nil,
		cmdLinePtr,
		nil,
		nil,
		true,
		windows.CREATE_NO_WINDOW,
		nil,
		nil,
		&si,
		&pi,
	)
	if err != nil {
		windows.CloseHandle(stdoutWrite)
		log.Printf("[TUN] Failed to run ipconfig: %v", err)
		return servers
	}

	windows.CloseHandle(stdoutWrite)
	windows.WaitForSingleObject(pi.Process, windows.INFINITE)
	windows.CloseHandle(pi.Process)
	windows.CloseHandle(pi.Thread)

	// Read output
	output := make([]byte, 65536)
	var bytesRead uint32
	windows.ReadFile(stdoutRead, output, &bytesRead, nil)

	// Parse output for DNS servers
	lines := string(output[:bytesRead])
	inDNS := false
	for _, line := range splitLines(lines) {
		line = trimSpace(line)
		if containsString(line, "DNS Servers") {
			inDNS = true
			// Extract IP from this line
			if idx := indexString(line, ":"); idx != -1 {
				ip := trimSpace(line[idx+1:])
				if isValidIP(ip) {
					servers = append(servers, ip)
				}
			}
		} else if inDNS {
			// Continuation of DNS servers (indented lines)
			if len(line) > 0 && (line[0] == ' ' || line[0] == '\t' || isValidIP(line)) {
				ip := trimSpace(line)
				if isValidIP(ip) {
					servers = append(servers, ip)
				}
			} else if len(line) > 0 {
				inDNS = false
			}
		}
	}

	return servers
}

// Helper functions for string parsing
func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			line := s[start:i]
			if len(line) > 0 && line[len(line)-1] == '\r' {
				line = line[:len(line)-1]
			}
			lines = append(lines, line)
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

func trimSpace(s string) string {
	start := 0
	end := len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t' || s[start] == '\r' || s[start] == '\n') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t' || s[end-1] == '\r' || s[end-1] == '\n') {
		end--
	}
	return s[start:end]
}

func containsString(s, substr string) bool {
	return indexString(s, substr) != -1
}

func indexString(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}

func isValidIP(s string) bool {
	// Simple IPv4 validation
	if len(s) < 7 || len(s) > 15 {
		return false
	}
	dots := 0
	for _, c := range s {
		if c == '.' {
			dots++
		} else if c < '0' || c > '9' {
			return false
		}
	}
	return dots == 3
}

// isLocalNetworkIP checks if an IP is in a private network range
// These should not be routed through TUN to avoid loops
func isLocalNetworkIP(ip string) bool {
	// Parse the IP to check ranges
	parts := splitDottedIP(ip)
	if len(parts) != 4 {
		return false
	}

	first := parts[0]
	second := parts[1]

	// 10.0.0.0/8 (10.x.x.x)
	if first == 10 {
		return true
	}

	// 172.16.0.0/12 (172.16.x.x - 172.31.x.x)
	if first == 172 && second >= 16 && second <= 31 {
		return true
	}

	// 192.168.0.0/16 (192.168.x.x)
	if first == 192 && second == 168 {
		return true
	}

	// 127.0.0.0/8 (loopback)
	if first == 127 {
		return true
	}

	// 169.254.0.0/16 (link-local)
	if first == 169 && second == 254 {
		return true
	}

	return false
}

// splitDottedIP splits an IP string into octets
func splitDottedIP(ip string) []int {
	var parts []int
	start := 0
	for i := 0; i <= len(ip); i++ {
		if i == len(ip) || ip[i] == '.' {
			if i > start {
				num := 0
				for j := start; j < i; j++ {
					num = num*10 + int(ip[j]-'0')
				}
				parts = append(parts, num)
			}
			start = i + 1
		}
	}
	return parts
}

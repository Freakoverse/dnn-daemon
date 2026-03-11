// Package capture provides DNS packet capture using WinDivert on Windows.
// WinDivert intercepts packets BEFORE routing, avoiding the loop issues
// we had with TUN-based routing.
//
// The WinDivert driver files (WinDivert.dll and WinDivert64.sys) are embedded
// directly in the binary, enabling single-file distribution on Windows.
package capture

import (
	"crypto/tls"
	"crypto/x509"
	_ "embed"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"dnn-daemon/internal/certverify"
	"dnn-daemon/internal/detector"
	"dnn-daemon/internal/mapper"
	"dnn-daemon/internal/resolver"

	"github.com/miekg/dns"
)

// Embed the WinDivert driver files directly into the binary
//
//go:embed drivers/WinDivert.dll
var embeddedWinDivertDLL []byte

//go:embed drivers/WinDivert64.sys
var embeddedWinDivert64Sys []byte

var (
	windivertDLL           *syscall.LazyDLL
	windivertOpen          *syscall.LazyProc
	windivertRecv          *syscall.LazyProc
	windivertSend          *syscall.LazyProc
	windivertClose         *syscall.LazyProc
	windivertCalcChecksums *syscall.LazyProc

	windivertTempDir string // temp directory for extracted driver files
)

func init() {
	// Extract embedded WinDivert files to a temp directory
	dir, err := extractWinDivertFiles()
	if err != nil {
		log.Printf("[Capture] Warning: failed to extract embedded WinDivert files: %v", err)
		log.Printf("[Capture] Falling back to loading WinDivert.dll from current directory")
		windivertDLL = syscall.NewLazyDLL("WinDivert.dll")
	} else {
		windivertTempDir = dir
		dllPath := filepath.Join(dir, "WinDivert.dll")
		windivertDLL = syscall.NewLazyDLL(dllPath)
		log.Printf("[Capture] Loaded embedded WinDivert from %s", dir)
	}

	windivertOpen = windivertDLL.NewProc("WinDivertOpen")
	windivertRecv = windivertDLL.NewProc("WinDivertRecv")
	windivertSend = windivertDLL.NewProc("WinDivertSend")
	windivertClose = windivertDLL.NewProc("WinDivertClose")
	windivertCalcChecksums = windivertDLL.NewProc("WinDivertHelperCalcChecksums")
}

// extractWinDivertFiles writes the embedded WinDivert.dll and WinDivert64.sys
// to a temporary directory so they can be loaded at runtime.
// The .sys file must be in the same directory as the .dll because WinDivert
// loads the kernel driver from its own directory automatically.
func extractWinDivertFiles() (string, error) {
	dir, err := os.MkdirTemp("", "dnn-windivert-*")
	if err != nil {
		return "", fmt.Errorf("failed to create temp directory: %w", err)
	}

	dllPath := filepath.Join(dir, "WinDivert.dll")
	if err := os.WriteFile(dllPath, embeddedWinDivertDLL, 0644); err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("failed to write WinDivert.dll: %w", err)
	}

	sysPath := filepath.Join(dir, "WinDivert64.sys")
	if err := os.WriteFile(sysPath, embeddedWinDivert64Sys, 0644); err != nil {
		os.RemoveAll(dir)
		return "", fmt.Errorf("failed to write WinDivert64.sys: %w", err)
	}

	return dir, nil
}

// CleanupWinDivert removes the temporary directory containing extracted driver files.
// Call this when the daemon is shutting down.
func CleanupWinDivert() {
	if windivertTempDir != "" {
		if err := os.RemoveAll(windivertTempDir); err != nil {
			log.Printf("[Capture] Warning: failed to clean up WinDivert temp dir: %v", err)
		} else {
			log.Printf("[Capture] Cleaned up WinDivert temp dir: %s", windivertTempDir)
		}
		windivertTempDir = ""
	}
}

// WinDivert layer constants
const (
	WINDIVERT_LAYER_NETWORK = 0
)

// WinDivertAddress structure for WinDivert 2.x
// This must match the exact memory layout expected by WinDivert
type WinDivertAddress struct {
	Timestamp int64    // 8 bytes
	Layer     uint32   // 4 bytes (layer + event + flags combined for alignment)
	Length    uint32   // 4 bytes
	Network   struct { // 16 bytes
		IfIdx    uint32
		SubIfIdx uint32
		_        [8]byte
	}
}

// Capture handles DNS packet interception using WinDivert
type Capture struct {
	handle   uintptr
	cache    *mapper.Cache
	resolver *resolver.Resolver

	running bool
	wg      sync.WaitGroup
	mu      sync.RWMutex
}

// Config for the capture
type Config struct {
	Cache    *mapper.Cache
	Resolver *resolver.Resolver
}

// New creates a new WinDivert-based DNS capture
func New(cfg *Config) (*Capture, error) {
	// Open WinDivert with filter for outbound DNS (UDP port 53)
	filter := "outbound and udp.DstPort == 53"
	filterPtr, _ := syscall.BytePtrFromString(filter)

	handle, _, err := windivertOpen.Call(
		uintptr(unsafe.Pointer(filterPtr)),
		WINDIVERT_LAYER_NETWORK,
		0, // priority
		0, // flags
	)

	if handle == 0 || handle == ^uintptr(0) {
		return nil, fmt.Errorf("WinDivertOpen failed: %v", err)
	}

	log.Printf("[Capture] Opened WinDivert handle for DNS interception")

	return &Capture{
		handle:   handle,
		cache:    cfg.Cache,
		resolver: cfg.Resolver,
	}, nil
}

// Start begins capturing DNS packets
func (c *Capture) Start() error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return nil
	}
	c.running = true
	c.mu.Unlock()

	c.wg.Add(1)
	go c.captureLoop()

	log.Printf("[Capture] Started DNS packet capture")
	return nil
}

// Stop stops the capture
func (c *Capture) Stop() {
	c.mu.Lock()
	c.running = false
	c.mu.Unlock()

	windivertClose.Call(c.handle)
	c.wg.Wait()

	log.Printf("[Capture] Stopped DNS packet capture")
}

func (c *Capture) captureLoop() {
	defer c.wg.Done()

	packet := make([]byte, 65535)
	addr := make([]byte, 64) // Use raw bytes for address, large enough for any version
	var packetLen uint32

	log.Printf("[Capture] Entering capture loop...")

	for {
		c.mu.RLock()
		if !c.running {
			c.mu.RUnlock()
			return
		}
		c.mu.RUnlock()

		// Receive packet
		ret, _, lastErr := windivertRecv.Call(
			c.handle,
			uintptr(unsafe.Pointer(&packet[0])),
			uintptr(len(packet)),
			uintptr(unsafe.Pointer(&packetLen)),
			uintptr(unsafe.Pointer(&addr[0])),
		)

		if ret == 0 {
			// Check if it's a real error or just no packet available
			if lastErr != nil && lastErr.Error() != "The operation completed successfully." {
				log.Printf("[Capture] WinDivertRecv error: %v", lastErr)
			}
			continue
		}

		// Process the packet
		c.processPacket(packet[:packetLen], addr)
	}
}

func (c *Capture) processPacket(packet []byte, addr []byte) {
	if len(packet) < 20 {
		c.reinject(packet, addr)
		return
	}

	// Parse IP header
	version := packet[0] >> 4
	if version != 4 {
		c.reinject(packet, addr)
		return
	}

	ihl := int(packet[0]&0x0f) * 4
	if len(packet) < ihl+8 {
		c.reinject(packet, addr)
		return
	}

	protocol := packet[9]
	if protocol != 17 { // UDP
		c.reinject(packet, addr)
		return
	}

	srcIP := net.IP(packet[12:16])
	dstIP := net.IP(packet[16:20])

	// Parse UDP header
	udp := packet[ihl:]
	srcPort := binary.BigEndian.Uint16(udp[0:2])
	dstPort := binary.BigEndian.Uint16(udp[2:4])

	if dstPort != 53 {
		c.reinject(packet, addr)
		return
	}

	// Parse DNS
	dnsData := udp[8:]
	msg := new(dns.Msg)
	if err := msg.Unpack(dnsData); err != nil {
		log.Printf("[Capture] DNS parse error: %v", err)
		c.reinject(packet, addr)
		return
	}

	if len(msg.Question) == 0 {
		c.reinject(packet, addr)
		return
	}

	qname := msg.Question[0].Name
	name := qname
	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}

	// Log all DNS queries for debugging
	isDNN := detector.IsDNNName(name)

	// Check if DNN
	if isDNN {
		log.Printf("[Capture] DNN query: %s", name)
		c.handleDNN(packet, addr, msg, srcIP, srcPort, dstIP, dstPort, name, ihl)
	} else {
		// Forward non-DNN queries normally
		c.reinject(packet, addr)
	}
}

func (c *Capture) handleDNN(origPacket []byte, addr []byte, msg *dns.Msg,
	srcIP net.IP, srcPort uint16, dstIP net.IP, dstPort uint16, name string, ihl int) {

	// Get the DNN TLD for logging
	dnnTLD := detector.GetTLD(name)

	// Determine what to resolve:
	// - If name == TLD (e.g., "nabtaabout"), resolve the TLD directly
	// - If name has subdomain (e.g., "asdasd.nabtaabout"), pass the full name
	//   so the node can validate the subdomain against 61600 o-tags
	nameToResolve := name
	if name == dnnTLD {
		// Bare DNN name, no subdomain
		nameToResolve = dnnTLD
	} else {
		// Has subdomain - extract just the immediate subdomain + TLD
		// e.g., "asdasd.nabtaabout" -> "asdasd.nabtaabout" (pass as-is)
		// e.g., "www.asdasd.nabtaabout" -> use last subdomain before TLD
		parts := strings.Split(strings.ToLower(name), ".")
		for i, part := range parts {
			if part == dnnTLD && i > 0 {
				// Take the part immediately before the TLD
				nameToResolve = parts[i-1] + "." + dnnTLD
				break
			}
		}
	}

	// Resolve via DNN node - pass full name including subdomain
	resolution, err := c.resolver.Resolve(nameToResolve)
	if err != nil {
		log.Printf("[Capture] Failed to resolve DNN name %s: %v", nameToResolve, err)
		c.reinject(origPacket, addr)
		return
	}

	// Generate interception IPv6 for this DNN name
	// This is the "ticket" that travels through the stack
	interceptionIPv6 := mapper.NpubToIPv6(name)

	log.Printf("[Capture] Resolved %s -> %s:%d (IPv6: %s)", nameToResolve, resolution.IP, resolution.Port, interceptionIPv6.String())

	// Cache the full resolution including transports
	var certPEM string
	if resolution.Cert != nil {
		certPEM = resolution.Cert.PEM
	}

	// Determine which IP to verify against
	// For subdomains with specific IPs in A records, verify against THAT IP
	verifyIP := resolution.IP
	subdomainPart := ""

	// Check if the original query was for a subdomain
	// e.g., name="blossom.freakoverse.nabtaabove", nameToResolve="freakoverse.nabtaabove"
	if name != nameToResolve && strings.HasSuffix(name, "."+nameToResolve) {
		subdomainPart = strings.TrimSuffix(name, "."+nameToResolve)
		// Look for subdomain-specific IP in A records
		if resolution.SubdomainIPs != nil {
			if subIP, found := resolution.SubdomainIPs[subdomainPart]; found {
				log.Printf("[Capture] Subdomain '%s' has specific IP: %s (parent: %s)", subdomainPart, subIP, resolution.IP)
				verifyIP = subIP
			}
		}
	}

	// Verify server cert matches declared cert
	// IMPORTANT: Verify against the ACTUAL IP that will serve this domain
	verified := c.verifyServerCert(verifyIP, resolution.Port, nameToResolve, certPEM)

	// Register the mapping: name -> IPv6 (allows lookup by IPv6 later)
	c.cache.Register(name)

	// Store full resolution data including subdomain IPs for routing
	c.cache.RegisterWithIPAndSubdomains(name, resolution.IP, resolution.Port, certPEM, resolution.SubdomainIPs)
	if verified {
		c.cache.SetCertVerified(name, true, "")
		log.Printf("[Capture] ✓ Cert verified for %s (verified IP: %s)", nameToResolve, verifyIP)
	} else {
		c.cache.SetCertVerified(name, false, "cert verification failed")
		log.Printf("[Capture] ⚠️ Cert verification FAILED for %s (verified IP: %s)", nameToResolve, verifyIP)
	}

	// Build DNS response
	resp := new(dns.Msg)
	resp.SetReply(msg)
	resp.Authoritative = true

	qtype := msg.Question[0].Qtype

	switch qtype {
	case dns.TypeA:
		// Return 127.0.0.1 for A records (IPv4 fallback)
		// This is for compatibility when IPv6 doesn't work
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   msg.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: net.ParseIP("127.0.0.1"),
		})
	case dns.TypeAAAA:
		// Return the interception IPv6 for AAAA records
		// This is the primary method - the IPv6 "ticket"
		resp.Answer = append(resp.Answer, &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   msg.Question[0].Name,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			AAAA: interceptionIPv6,
		})
	default:
		// Unsupported query type, pass through
		c.reinject(origPacket, addr)
		return
	}

	// Pack response
	respData, err := resp.Pack()
	if err != nil {
		log.Printf("[Capture] Failed to pack DNS response: %v", err)
		c.reinject(origPacket, addr)
		return
	}

	// Build response packet (swap src/dst)
	respPacket := c.buildResponsePacket(origPacket, ihl, dstIP, srcIP, dstPort, srcPort, respData)

	// Swap direction (inbound response) - set Outbound bit to 0
	// WinDivert 2.x address structure:
	//   Bytes 0-7: Timestamp (INT64)
	//   Byte 8: Layer (UINT8)
	//   Byte 9: Event (UINT8)
	//   Byte 10: Flags bitfield (Sniffed=bit0, Outbound=bit1, Loopback=bit2, ...)
	if len(addr) > 10 {
		addr[10] = addr[10] &^ 0x02 // Clear Outbound bit (bit 1)
	}

	// Inject response
	c.reinject(respPacket, addr)
}

func (c *Capture) buildResponsePacket(origPacket []byte, ihl int, srcIP, dstIP net.IP, srcPort, dstPort uint16, dnsData []byte) []byte {
	// Calculate sizes
	udpLen := 8 + len(dnsData)
	totalLen := ihl + udpLen

	packet := make([]byte, totalLen)

	// Copy original IP header and modify
	copy(packet[:ihl], origPacket[:ihl])

	// Swap source and destination IP
	copy(packet[12:16], srcIP.To4())
	copy(packet[16:20], dstIP.To4())

	// Update total length
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))

	// Clear checksum (WinDivert will recalculate)
	packet[10] = 0
	packet[11] = 0

	// Build UDP header
	udp := packet[ihl:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	binary.BigEndian.PutUint16(udp[6:8], 0) // Checksum (WinDivert recalculates)

	// Copy DNS data
	copy(udp[8:], dnsData)

	return packet
}

func (c *Capture) reinject(packet []byte, addr []byte) {
	// Calculate IP and UDP checksums - critical for packet to be accepted
	// WinDivertHelperCalcChecksums(packet, packetLen, addr, flags)
	// flags = 0 means calculate all checksums
	windivertCalcChecksums.Call(
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&addr[0])),
		0, // flags: calculate all checksums
	)

	windivertSend.Call(
		c.handle,
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		0,
		uintptr(unsafe.Pointer(&addr[0])),
	)
}

// verifyServerCert connects to the server and verifies its cert matches the declared cert
func (c *Capture) verifyServerCert(ip string, port int, dnnName, declaredCertPEM string) bool {
	// If no declared cert, we can't verify
	if declaredCertPEM == "" {
		log.Printf("[Capture] No declared cert for %s", dnnName)
		return false
	}

	// Use HTTPS port
	if port == 0 || port == 80 {
		port = 443
	}

	addr := fmt.Sprintf("%s:%d", ip, port)
	log.Printf("[Capture] Connecting to %s to verify cert for %s...", addr, dnnName)

	// Connect to server with short timeout
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp",
		addr,
		&tls.Config{
			ServerName:         dnnName,
			InsecureSkipVerify: true, // We do our own verification
		},
	)
	if err != nil {
		log.Printf("[Capture] Failed to connect to %s for cert verification: %v", addr, err)
		return false
	}
	defer conn.Close()

	// Get server's certificate
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		log.Printf("[Capture] Server %s returned no certificates", addr)
		return false
	}

	// Convert server cert to PEM
	serverCertPEM := c.certToPEM(certs[0])

	// Verify using certverify package
	result := certverify.VerifyCert(declaredCertPEM, serverCertPEM, dnnName)
	if !result.Valid {
		log.Printf("[Capture] ❌ Cert verification failed for %s: %v", dnnName, result.Error)
		return false
	}

	return true
}

// certToPEM converts an x509 certificate to PEM format
func (c *Capture) certToPEM(cert *x509.Certificate) string {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return string(pem.EncodeToMemory(block))
}

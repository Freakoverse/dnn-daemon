// Package stack provides a userspace network stack for handling TUN packets.
//
// It intercepts DNS queries to detect DNN patterns and routes DNN traffic
// through the existing proxy infrastructure.
package stack

import (
	"encoding/binary"
	"log"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
	"dnn-daemon/internal/detector"
	"dnn-daemon/internal/mapper"
	"dnn-daemon/internal/resolver"
	"dnn-daemon/internal/tun"
)

// Stack handles packets from the TUN interface
type Stack struct {
	device   tun.Device
	cache    *mapper.Cache
	resolver *resolver.Resolver

	// DNS handling
	upstreamDNS string // Upstream DNS for non-DNN queries
	localIP     net.IP // Local non-TUN IP for bypassing TUN routes

	// State
	running bool
	wg      sync.WaitGroup
	mu      sync.RWMutex
}

// Config for the network stack
type StackConfig struct {
	// Cache is the DNN name cache
	Cache *mapper.Cache

	// Resolver is the DNN resolver
	Resolver *resolver.Resolver

	// UpstreamDNS for non-DNN queries (default: 8.8.8.8:53)
	UpstreamDNS string

	// LocalIP is the non-TUN interface IP to use for upstream queries
	// If empty, will be auto-detected
	LocalIP string
}

// New creates a new network stack with the given TUN device
func New(device tun.Device, cfg *StackConfig) *Stack {
	if cfg.UpstreamDNS == "" {
		// Use Level3 DNS (4.2.2.2) as upstream - it's NOT in our TUN route list
		// so it won't loop back through TUN
		cfg.UpstreamDNS = "4.2.2.2:53"
	}

	// Auto-detect local IP if not specified
	localIP := net.ParseIP(cfg.LocalIP)
	if localIP == nil {
		localIP = detectNonTUNIP()
		if localIP != nil {
			log.Printf("[Stack] Detected non-TUN IP for upstream: %s", localIP)
		}
	}

	return &Stack{
		device:      device,
		cache:       cfg.Cache,
		resolver:    cfg.Resolver,
		upstreamDNS: cfg.UpstreamDNS,
		localIP:     localIP,
	}
}

// detectNonTUNIP finds a local IP that's not on the TUN interface
func detectNonTUNIP() net.IP {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil
	}

	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok {
			ip := ipnet.IP.To4()
			if ip == nil {
				continue // Skip IPv6
			}
			// Skip loopback (127.x.x.x)
			if ip[0] == 127 {
				continue
			}
			// Skip TUN address (10.0.85.x)
			if ip[0] == 10 && ip[1] == 0 && ip[2] == 85 {
				continue
			}
			// Skip link-local (169.254.x.x) - not routable
			if ip[0] == 169 && ip[1] == 254 {
				continue
			}
			// Found a non-TUN, non-loopback, non-link-local IPv4 address
			return ip
		}
	}
	return nil
}

// Start begins processing packets from the TUN interface
func (s *Stack) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = true
	s.mu.Unlock()

	s.wg.Add(1)
	go s.readLoop()

	log.Printf("[Stack] Started packet processing on %s", s.device.Name())
	return nil
}

// Stop stops the network stack
func (s *Stack) Stop() {
	s.mu.Lock()
	s.running = false
	s.mu.Unlock()

	s.device.Close()
	s.wg.Wait()

	log.Printf("[Stack] Stopped packet processing")
}

// readLoop reads packets from the TUN and processes them
func (s *Stack) readLoop() {
	defer s.wg.Done()

	buf := make([]byte, 65535) // Max IP packet size

	for {
		s.mu.RLock()
		if !s.running {
			s.mu.RUnlock()
			return
		}
		s.mu.RUnlock()

		n, err := s.device.Read(buf)
		if err != nil {
			if err == tun.ErrClosed {
				return
			}
			log.Printf("[Stack] Read error: %v", err)
			continue
		}

		if n < 20 { // Minimum IP header size
			continue
		}

		// Process packet
		s.processPacket(buf[:n])
	}
}

// processPacket handles an incoming IP packet
func (s *Stack) processPacket(packet []byte) {
	// Check IP version
	version := packet[0] >> 4

	switch version {
	case 4:
		s.processIPv4(packet)
	case 6:
		s.processIPv6(packet)
	default:
		// Unknown IP version, ignore
	}
}

// processIPv4 handles IPv4 packets
func (s *Stack) processIPv4(packet []byte) {
	if len(packet) < 20 {
		return
	}

	// Parse IPv4 header
	ihl := int(packet[0]&0x0f) * 4
	if len(packet) < ihl {
		return
	}

	protocol := packet[9]
	srcIP := net.IP(packet[12:16])
	dstIP := net.IP(packet[16:20])

	// Check if it's UDP (DNS) or TCP
	switch protocol {
	case 17: // UDP
		if len(packet) < ihl+8 {
			return
		}
		s.processUDP(packet[ihl:], srcIP, dstIP, false)
	case 6: // TCP
		if len(packet) < ihl+20 {
			return
		}
		s.processTCP(packet[ihl:], srcIP, dstIP, false)
	}
}

// processIPv6 handles IPv6 packets
func (s *Stack) processIPv6(packet []byte) {
	if len(packet) < 40 {
		return
	}

	// Check if destination is in fd00::/8 (DNN transport range)
	if packet[24] == 0xfd {
		// This is a DNN transport packet - handle via transport layer
		s.processDNNTransport(packet)
		return
	}

	nextHeader := packet[6]
	srcIP := net.IP(packet[8:24])
	dstIP := net.IP(packet[24:40])

	// Check if it's UDP (DNS)
	switch nextHeader {
	case 17: // UDP
		if len(packet) < 48 {
			return
		}
		s.processUDP(packet[40:], srcIP, dstIP, true)
	case 6: // TCP
		if len(packet) < 60 {
			return
		}
		s.processTCP(packet[40:], srcIP, dstIP, true)
	}
}

// processUDP handles UDP packets (mainly for DNS)
func (s *Stack) processUDP(payload []byte, srcIP, dstIP net.IP, isIPv6 bool) {
	if len(payload) < 8 {
		return
	}

	srcPort := binary.BigEndian.Uint16(payload[0:2])
	dstPort := binary.BigEndian.Uint16(payload[2:4])
	// length := binary.BigEndian.Uint16(payload[4:6])
	// checksum := binary.BigEndian.Uint16(payload[6:8])

	udpData := payload[8:]

	// Check if this is a DNS query (port 53)
	if dstPort == 53 {
		s.processDNSQuery(udpData, srcIP, srcPort, dstIP, isIPv6)
	}
}

// processDNSQuery handles DNS queries
func (s *Stack) processDNSQuery(data []byte, srcIP net.IP, srcPort uint16, dstIP net.IP, isIPv6 bool) {
	// Parse DNS message
	msg := new(dns.Msg)
	if err := msg.Unpack(data); err != nil {
		return
	}

	if len(msg.Question) == 0 {
		return
	}

	qname := msg.Question[0].Name
	qtype := msg.Question[0].Qtype

	// Remove trailing dot
	name := qname
	if len(name) > 0 && name[len(name)-1] == '.' {
		name = name[:len(name)-1]
	}

	// Check if this is a DNN name
	if detector.IsDNNName(name) {
		log.Printf("[Stack] DNS query for DNN name: %s", name)
		s.handleDNNQuery(msg, srcIP, srcPort, dstIP, isIPv6, name, qtype)
		return
	}

	// Forward non-DNN queries upstream
	s.forwardDNS(msg, srcIP, srcPort, dstIP, isIPv6)
}

// handleDNNQuery handles DNS queries for DNN names
func (s *Stack) handleDNNQuery(msg *dns.Msg, srcIP net.IP, srcPort uint16, dstIP net.IP, isIPv6 bool, dnnName string, qtype uint16) {
	// Resolve the full DNN name (including subdomain) via DNN node
	// This ensures the node checks if the subdomain exists in the connection content
	resolution, err := s.resolver.Resolve(dnnName)
	if err != nil {
		log.Printf("[Stack] Failed to resolve DNN name %s: %v", dnnName, err)
		// Send NXDOMAIN response
		s.sendDNSResponse(msg, srcIP, srcPort, dstIP, isIPv6, nil)
		return
	}

	// Cache the resolution
	var certPEM string
	if resolution.Cert != nil {
		certPEM = resolution.Cert.PEM
	}
	s.cache.RegisterWithIP(dnnName, resolution.IP, resolution.Port, certPEM)

	// Build response based on query type
	resp := new(dns.Msg)
	resp.SetReply(msg)
	resp.Authoritative = true

	switch qtype {
	case dns.TypeA:
		// Return 127.0.0.1 to route through our proxy
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
		// Return fd00::/8 address for IPv6 transport interception
		if resolution.HasTransports() && resolution.InterceptionIPv6 != "" {
			ip := net.ParseIP(resolution.InterceptionIPv6)
			if ip != nil {
				resp.Answer = append(resp.Answer, &dns.AAAA{
					Hdr: dns.RR_Header{
						Name:   msg.Question[0].Name,
						Rrtype: dns.TypeAAAA,
						Class:  dns.ClassINET,
						Ttl:    300,
					},
					AAAA: ip,
				})
			}
		}
	}

	s.sendDNSResponse(resp, srcIP, srcPort, dstIP, isIPv6, resp)
}

// sendDNSResponse sends a DNS response back through the TUN
func (s *Stack) sendDNSResponse(origMsg *dns.Msg, dstIP net.IP, dstPort uint16, srcIP net.IP, isIPv6 bool, resp *dns.Msg) {
	if resp == nil {
		// Send NXDOMAIN
		resp = new(dns.Msg)
		resp.SetRcode(origMsg, dns.RcodeNameError)
	}

	// Pack DNS response
	dnsData, err := resp.Pack()
	if err != nil {
		log.Printf("[Stack] Failed to pack DNS response: %v", err)
		return
	}

	// Build UDP packet
	udpLen := 8 + len(dnsData)
	udpPacket := make([]byte, udpLen)
	binary.BigEndian.PutUint16(udpPacket[0:2], 53) // Src port
	binary.BigEndian.PutUint16(udpPacket[2:4], dstPort)
	binary.BigEndian.PutUint16(udpPacket[4:6], uint16(udpLen))
	binary.BigEndian.PutUint16(udpPacket[6:8], 0) // Checksum (optional for IPv4)
	copy(udpPacket[8:], dnsData)

	// Build IP packet
	var ipPacket []byte
	if isIPv6 {
		ipPacket = s.buildIPv6Packet(srcIP, dstIP, 17, udpPacket)
	} else {
		ipPacket = s.buildIPv4Packet(srcIP, dstIP, 17, udpPacket)
	}

	// Write to TUN
	if _, err := s.device.Write(ipPacket); err != nil {
		log.Printf("[Stack] Failed to send DNS response: %v", err)
	}
}

// forwardDNS forwards a DNS query to upstream and returns response
func (s *Stack) forwardDNS(msg *dns.Msg, srcIP net.IP, srcPort uint16, dstIP net.IP, isIPv6 bool) {
	// Use our configured upstream DNS (4.2.2.2) which is NOT routed through TUN
	// Don't use dstIP (the packet's destination) because that's routed through TUN and loops
	upstreamAddr := s.upstreamDNS

	// CRITICAL: Bind to the non-TUN interface IP to bypass TUN routing
	// Otherwise the packet would loop back through our TUN
	var localAddr net.Addr
	if s.localIP != nil {
		localAddr = &net.UDPAddr{IP: s.localIP, Port: 0}
	}

	dialer := &net.Dialer{
		Timeout:   2 * time.Second,
		LocalAddr: localAddr,
	}

	conn, err := dialer.Dial("udp", upstreamAddr)
	if err != nil {
		log.Printf("[Stack] Upstream DNS dial error: %v", err)
		return
	}
	defer conn.Close()

	// Set deadline
	conn.SetDeadline(time.Now().Add(2 * time.Second))

	// Send query
	dnsData, _ := msg.Pack()
	if _, err := conn.Write(dnsData); err != nil {
		log.Printf("[Stack] Upstream DNS write error: %v", err)
		return
	}

	// Read response
	respBuf := make([]byte, 65535)
	n, err := conn.Read(respBuf)
	if err != nil {
		log.Printf("[Stack] Upstream DNS read error: %v", err)
		return
	}

	// Parse response
	resp := new(dns.Msg)
	if err := resp.Unpack(respBuf[:n]); err != nil {
		log.Printf("[Stack] Upstream DNS unpack error: %v", err)
		return
	}

	// Send response back through TUN
	s.sendDNSResponse(msg, srcIP, srcPort, dstIP, isIPv6, resp)
}

// processTCP handles TCP packets
func (s *Stack) processTCP(payload []byte, srcIP, dstIP net.IP, isIPv6 bool) {
	if len(payload) < 20 {
		return
	}

	// srcPort := binary.BigEndian.Uint16(payload[0:2])
	dstPort := binary.BigEndian.Uint16(payload[2:4])

	// Check if this is HTTPS to our proxy (127.0.0.1:443)
	if dstPort == 443 && dstIP.Equal(net.ParseIP("127.0.0.1")) {
		// This is already routed correctly to our HTTPS proxy
		// The TUN will forward it to localhost
		return
	}

	// Other TCP traffic - let it flow normally
}

// processDNNTransport handles packets destined for fd00::/8 (DNN transports)
func (s *Stack) processDNNTransport(packet []byte) {
	// Extract destination IPv6 from packet
	dstIP := net.IP(packet[24:40])

	// Look up the DNN name for this IPv6
	dnnName, ok := s.cache.LookupByIP(dstIP)
	if !ok {
		log.Printf("[Stack] Unknown DNN transport destination: %s", dstIP)
		return
	}

	log.Printf("[Stack] DNN transport packet for: %s", dnnName)
	// TODO: Handle transport (relay, tollgate, etc.)
}

// buildIPv4Packet builds an IPv4 packet
func (s *Stack) buildIPv4Packet(srcIP, dstIP net.IP, protocol byte, payload []byte) []byte {
	headerLen := 20
	totalLen := headerLen + len(payload)

	packet := make([]byte, totalLen)

	// Version (4) and IHL (5 = 20 bytes)
	packet[0] = 0x45
	// DSCP/ECN
	packet[1] = 0
	// Total length
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))
	// Identification
	binary.BigEndian.PutUint16(packet[4:6], 0)
	// Flags and fragment offset
	binary.BigEndian.PutUint16(packet[6:8], 0x4000) // Don't fragment
	// TTL
	packet[8] = 64
	// Protocol
	packet[9] = protocol
	// Header checksum (computed below)
	binary.BigEndian.PutUint16(packet[10:12], 0)
	// Source IP
	copy(packet[12:16], srcIP.To4())
	// Destination IP
	copy(packet[16:20], dstIP.To4())

	// Compute header checksum
	checksum := ipv4Checksum(packet[:20])
	binary.BigEndian.PutUint16(packet[10:12], checksum)

	// Copy payload
	copy(packet[20:], payload)

	return packet
}

// buildIPv6Packet builds an IPv6 packet
func (s *Stack) buildIPv6Packet(srcIP, dstIP net.IP, nextHeader byte, payload []byte) []byte {
	headerLen := 40
	totalLen := headerLen + len(payload)

	packet := make([]byte, totalLen)

	// Version (6), Traffic Class, Flow Label
	packet[0] = 0x60
	packet[1] = 0
	packet[2] = 0
	packet[3] = 0
	// Payload length
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(payload)))
	// Next header
	packet[6] = nextHeader
	// Hop limit
	packet[7] = 64
	// Source IP
	copy(packet[8:24], srcIP.To16())
	// Destination IP
	copy(packet[24:40], dstIP.To16())
	// Payload
	copy(packet[40:], payload)

	return packet
}

// ipv4Checksum computes the IPv4 header checksum
func ipv4Checksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i:]))
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

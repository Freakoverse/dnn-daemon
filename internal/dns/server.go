// Package dns provides a local DNS server for DNN domain resolution.
//
// This server intercepts ALL DNS queries and checks each one against the DNN
// pattern (n + 4 chars + BIP39 word). DNN queries are resolved via DNN nodes;
// other queries are forwarded to upstream DNS.
package dns

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"dnn-daemon/internal/certverify"
	"dnn-daemon/internal/detector"
	"dnn-daemon/internal/dnsconfig"
	"dnn-daemon/internal/mapper"
	"dnn-daemon/internal/resolver"

	"github.com/miekg/dns"
)

// Server is a DNS server that detects DNN names by pattern
type Server struct {
	listenAddr string
	cache      *mapper.Cache
	resolver   *resolver.Resolver
	server     *dns.Server
}

// New creates a new DNS server
func New(listenAddr, _ string, cache *mapper.Cache, res *resolver.Resolver) *Server {
	return &Server{
		listenAddr: listenAddr,
		cache:      cache,
		resolver:   res,
	}
}

// Start starts the DNS server
func (s *Server) Start() error {
	// Handle ALL queries - we'll detect DNN names by pattern
	dns.HandleFunc(".", s.handleQuery)

	s.server = &dns.Server{
		Addr: s.listenAddr,
		Net:  "udp",
	}

	log.Printf("[DNS] Starting DNS server on %s (pattern-based DNN detection)", s.listenAddr)
	return s.server.ListenAndServe()
}

// Stop stops the DNS server
func (s *Server) Stop() error {
	if s.server != nil {
		return s.server.Shutdown()
	}
	return nil
}

// handleQuery handles all DNS queries, detecting DNN names by pattern
func (s *Server) handleQuery(w dns.ResponseWriter, r *dns.Msg) {
	// Check if any question is a DNN name
	for _, q := range r.Question {
		name := strings.TrimSuffix(q.Name, ".")

		if detector.IsDNNName(name) {
			// This is a DNN name - handle it ourselves
			s.handleDNN(w, r, name)
			return
		}
	}

	// Not a DNN name - forward to upstream
	s.forwardToUpstream(w, r)
}

// handleDNN handles queries for DNN names
func (s *Server) handleDNN(w dns.ResponseWriter, r *dns.Msg, dnnName string) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	for _, q := range r.Question {
		name := strings.TrimSuffix(q.Name, ".")

		switch q.Qtype {
		case dns.TypeA:
			// Return IPv4 A record with resolved IP
			s.handleA(m, q, name)
		case dns.TypeAAAA:
			// Return IPv6 AAAA record (fd00::/8 fake address)
			s.handleAAAA(m, q, name)
		default:
			// Return empty response for other types
		}
	}

	w.WriteMsg(m)
}

// handleA handles A record queries
// Verifies cert at DNS time: if valid → return 127.0.0.1 (proxy), if invalid → return real IP (direct)
func (s *Server) handleA(m *dns.Msg, q dns.Question, dnnName string) {
	// GetTLD extracts the actual DNN ID (handles Windows search suffix pollution)
	// e.g., "nabobabout.nabceabsurd" → "nabobabout" (leftmost DNN ID)
	// e.g., "freakoverse.nabobabout.nabceabsurd" → "nabobabout" (first valid DNN ID)
	dnnTLD := detector.GetTLD(dnnName)

	// Determine if there's a domain prefix (e.g., "freakoverse" in "freakoverse.nabobabout")
	// This is NOT the same as Windows search suffix - it's an intentional domain under the TLD
	dnnName = strings.ToLower(strings.TrimSuffix(dnnName, "."))
	dnnTLD = strings.ToLower(dnnTLD)

	// Calculate the name to resolve
	// Find where the DNN TLD is in the name (handles Windows search suffix)
	nameToResolve := dnnTLD // Default: just the TLD

	// Find the position of the DNN TLD in the domain name
	tldIndex := strings.Index(dnnName, dnnTLD)
	if tldIndex > 0 && dnnName[tldIndex-1] == '.' {
		// There's something before the TLD
		prefix := dnnName[:tldIndex-1] // Everything before the TLD
		// Take only the immediate prefix (last part before the TLD)
		prefixParts := strings.Split(prefix, ".")
		domainPrefix := prefixParts[len(prefixParts)-1]

		// Only include domain prefix if it's not itself a valid DNN ID (search suffix case)
		if !detector.IsDNNName(domainPrefix) && domainPrefix != "" {
			nameToResolve = domainPrefix + "." + dnnTLD
		}
	}

	log.Printf("[DNS] A query for: %s (resolved TLD: %s, resolving: %s)", dnnName, dnnTLD, nameToResolve)

	// Resolve via DNN node
	resolution, err := s.resolver.Resolve(nameToResolve)
	if err != nil {
		log.Printf("[DNS] Resolution failed for %s: %v", nameToResolve, err)
		return // Return empty response (NXDOMAIN behavior)
	}

	// Get declared cert PEM from DNN node
	declaredCertPEM := ""
	if resolution.Cert != nil && resolution.Cert.PEM != "" {
		declaredCertPEM = resolution.Cert.PEM
	}

	// Determine which IP to return based on cert verification
	var returnIP net.IP

	// For subdomains, check if there's a specific IP in SubdomainIPs
	// This determines which server to verify against
	verifyIP := resolution.IP
	verifyPort := resolution.Port

	// Check if the original query was for a subdomain of nameToResolve
	// e.g., dnnName="blossom.freakoverse.nabtaabove", nameToResolve="freakoverse.nabtaabove"
	subdomainPart := ""
	if dnnName != nameToResolve && strings.HasSuffix(dnnName, "."+nameToResolve) {
		subdomainPart = strings.TrimSuffix(dnnName, "."+nameToResolve)
		// Look for subdomain-specific IP
		if resolution.SubdomainIPs != nil {
			if subIP, found := resolution.SubdomainIPs[subdomainPart]; found {
				log.Printf("[DNS] Subdomain %s has specific IP: %s (parent: %s)", subdomainPart, subIP, resolution.IP)
				verifyIP = subIP
			}
		}
	}

	// Verify the server's cert against the declared cert
	// IMPORTANT: Verify against the ACTUAL IP that will serve this domain
	verified := s.verifyServerCert(verifyIP, verifyPort, nameToResolve, declaredCertPEM)

	// Check for transport-first resolution (NIP-DN)
	// If transports are configured and interception_ipv6 exists, use that for fd00::/8 interception
	if resolution.HasTransports() && resolution.InterceptionIPv6 != "" {
		returnIP = net.ParseIP(resolution.InterceptionIPv6)
		if returnIP != nil {
			log.Printf("[DNS] 🚀 Transport-first for %s - returning %s", nameToResolve, resolution.InterceptionIPv6)
			// Cache the resolution with transport info for proxy to use
			s.cache.RegisterWithIP(nameToResolve, resolution.IP, resolution.Port, declaredCertPEM)
			// Set verification status for transport-first
			s.cache.SetCertVerified(nameToResolve, verified, "")
			// Create AAAA record for IPv6
			rr := &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   q.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    300,
				},
				AAAA: returnIP,
			}
			m.Answer = append(m.Answer, rr)
			return
		}
		log.Printf("[DNS] Warning: Invalid interception_ipv6: %s, falling back", resolution.InterceptionIPv6)
	}

	if verified {
		// Cert is valid - route through proxy (127.0.0.1)
		returnIP = net.ParseIP("127.0.0.1").To4()
		log.Printf("[DNS] ✓ Cert verified for %s - routing through proxy", nameToResolve)

		// Cache the resolution for the proxy to use
		s.cache.RegisterWithIP(nameToResolve, resolution.IP, resolution.Port, declaredCertPEM)
		// Mark as verified so signer will sign with trusted CA
		s.cache.SetCertVerified(nameToResolve, true, "")
	} else {
		// Cert verification failed - return real IP (browser will see original cert & show warning)
		returnIP = net.ParseIP(resolution.IP).To4()
		if returnIP == nil {
			log.Printf("[DNS] Invalid IP from resolution: %s", resolution.IP)
			return
		}
		log.Printf("[DNS] ⚠️ Cert verification failed for %s - returning real IP %s (browser will show warning)", nameToResolve, resolution.IP)
		// Register but mark as NOT verified - signer will generate untrusted cert
		s.cache.RegisterWithIP(nameToResolve, resolution.IP, resolution.Port, declaredCertPEM)
		s.cache.SetCertVerified(nameToResolve, false, "cert verification failed")
	}

	// Create A record
	rr := &dns.A{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    300, // 5 min TTL for DNN (reduce DNS lookups)
		},
		A: returnIP,
	}

	m.Answer = append(m.Answer, rr)
}

// verifyServerCert connects to the server and verifies its cert matches the declared cert
func (s *Server) verifyServerCert(ip string, port int, dnnTLD, declaredCertPEM string) bool {
	// If no declared cert, we can't verify - use direct mode
	if declaredCertPEM == "" {
		log.Printf("[DNS] No declared cert for %s, using direct mode", dnnTLD)
		return false
	}

	// Use HTTPS port
	if port == 0 || port == 80 {
		port = 443
	}

	addr := fmt.Sprintf("%s:%d", ip, port)
	log.Printf("[DNS] Connecting to %s to verify cert for %s...", addr, dnnTLD)

	// Connect to server with short timeout
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 5 * time.Second},
		"tcp",
		addr,
		&tls.Config{
			ServerName:         dnnTLD,
			InsecureSkipVerify: true, // We do our own verification
		},
	)
	if err != nil {
		log.Printf("[DNS] Failed to connect to %s for cert verification: %v", addr, err)
		return false // Can't verify, use direct mode
	}
	defer conn.Close()

	// Get server's certificate
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		log.Printf("[DNS] Server %s returned no certificates", addr)
		return false
	}

	// Convert server cert to PEM
	serverCertPEM := certToPEM(certs[0])

	// Debug: log first 100 chars of each cert
	declaredPreview := declaredCertPEM
	if len(declaredPreview) > 100 {
		declaredPreview = declaredPreview[:100] + "..."
	}
	serverPreview := serverCertPEM
	if len(serverPreview) > 100 {
		serverPreview = serverPreview[:100] + "..."
	}
	log.Printf("[DNS] Declared cert preview: %s", declaredPreview)
	log.Printf("[DNS] Server cert preview: %s", serverPreview)

	// Verify using certverify package
	result := certverify.VerifyCert(declaredCertPEM, serverCertPEM, dnnTLD)
	if !result.Valid {
		log.Printf("[DNS] ❌ Cert verification failed for %s: %v", dnnTLD, result.Error)
		return false
	}

	log.Printf("[DNS] ✓ Cert verification passed for %s", dnnTLD)
	return true
}

// certToPEM converts an x509 certificate to PEM format
func certToPEM(cert *x509.Certificate) string {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return string(pem.EncodeToMemory(block))
}

// handleAAAA handles AAAA queries - returns fd00::/8 fake address
func (s *Server) handleAAAA(m *dns.Msg, q dns.Question, dnnName string) {
	// Extract the DNN TLD
	dnnTLD := detector.GetTLD(dnnName)
	log.Printf("[DNS] AAAA query for: %s (TLD: %s)", dnnName, dnnTLD)

	// Generate deterministic IPv6 address and cache the mapping
	ip := s.cache.Register(dnnTLD)

	log.Printf("[DNS] Returning %s for %s", ip, dnnName)

	// Create AAAA record
	rr := &dns.AAAA{
		Hdr: dns.RR_Header{
			Name:   q.Name,
			Rrtype: dns.TypeAAAA,
			Class:  dns.ClassINET,
			Ttl:    300, // 5 min TTL for DNN
		},
		AAAA: ip,
	}

	m.Answer = append(m.Answer, rr)
}

// forwardToUpstream forwards non-DNN queries to the CURRENT network's DNS
// This queries DHCP dynamically, so it works when roaming between networks
func (s *Server) forwardToUpstream(w dns.ResponseWriter, r *dns.Msg) {
	// Get current network's DNS servers (live DHCP lookup)
	upstreams := dnsconfig.GetCurrentUpstreams()

	c := new(dns.Client)
	for _, upstream := range upstreams {
		resp, _, err := c.Exchange(r, upstream)
		if err == nil {
			w.WriteMsg(resp)
			return
		}
	}

	// If all upstreams fail, return SERVFAIL
	m := new(dns.Msg)
	m.SetReply(r)
	m.Rcode = dns.RcodeServerFailure
	w.WriteMsg(m)
}

// LocalIP extracts the host from a listen address
func LocalIP(listenAddr string) string {
	host, _, _ := net.SplitHostPort(listenAddr)
	return host
}

// LocalIP returns the local DNS server address for configuration
func (s *Server) LocalIP() string {
	host, _, _ := net.SplitHostPort(s.listenAddr)
	return host
}

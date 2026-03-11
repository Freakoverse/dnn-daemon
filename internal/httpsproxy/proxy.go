// Package httpsproxy provides an HTTPS/HTTP interception proxy for DNN domains.
//
// The proxy intercepts connections to DNN domains (routed via 127.0.0.1),
// looks up the real server address from the DNS cache, then proxies the
// connection to the real server.
package httpsproxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"dnn-daemon/internal/ca"
	"dnn-daemon/internal/certverify"
	"dnn-daemon/internal/detector"
	"dnn-daemon/internal/mapper"
	"dnn-daemon/internal/resolver"
)

// certToPEM converts an x509 certificate to PEM format
func certToPEM(cert *x509.Certificate) string {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}
	return string(pem.EncodeToMemory(block))
}

// Proxy is an HTTPS/HTTP interception proxy for DNN domains
type Proxy struct {
	httpsAddr string
	httpAddr  string
	ipv6Addr  string // IPv6 listener for transport-first (fd00::/8)
	signer    *ca.Signer
	cache     *mapper.Cache
	resolver  *resolver.Resolver
	httpsLn   net.Listener
	httpLn    net.Listener
	ipv6Ln    net.Listener // IPv6 listener for transport interception
	wg        sync.WaitGroup
	stopCh    chan struct{}

	// Connection pool for upstream TLS connections (reduces handshake overhead)
	connPool     map[string]*tls.Conn // addr -> conn
	connPoolLock sync.Mutex
	connPoolTTL  time.Duration
}

// New creates a new proxy
func New(httpsAddr, httpAddr string, signer *ca.Signer, cache *mapper.Cache, res *resolver.Resolver) *Proxy {
	// Connect signer to cache for cert verification checks
	// This allows signer to generate untrusted certs when no declared cert exists
	signer.SetCertChecker(cache)

	return &Proxy{
		httpsAddr:   httpsAddr,
		httpAddr:    httpAddr,
		ipv6Addr:    "[::1]:443", // IPv6 localhost for transport interception
		signer:      signer,
		cache:       cache,
		resolver:    res,
		stopCh:      make(chan struct{}),
		connPool:    make(map[string]*tls.Conn),
		connPoolTTL: 30 * time.Second, // Keep connections alive for 30s
	}
}

// Start starts both HTTPS and HTTP proxies
func (p *Proxy) Start() error {
	// Start HTTPS proxy
	if err := p.startHTTPS(); err != nil {
		return err
	}

	// Start HTTP proxy
	if err := p.startHTTP(); err != nil {
		return err
	}

	// Start IPv6 listener for transport interception (non-fatal if fails)
	if err := p.startIPv6(); err != nil {
		log.Printf("[IPv6] Warning: Failed to start IPv6 listener: %v", err)
		log.Printf("[IPv6] Transport-first resolution will use fallback")
	}

	return nil
}

// startHTTPS starts the HTTPS proxy on port 443
func (p *Proxy) startHTTPS() error {
	tlsConfig := p.signer.GetTLSConfig()

	listener, err := tls.Listen("tcp", p.httpsAddr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to start HTTPS proxy: %w", err)
	}
	p.httpsLn = listener

	log.Printf("[HTTPS] Proxy listening on %s", p.httpsAddr)

	go p.acceptLoop(listener, true)
	return nil
}

// startHTTP starts the HTTP proxy on port 80
func (p *Proxy) startHTTP() error {
	listener, err := net.Listen("tcp", p.httpAddr)
	if err != nil {
		return fmt.Errorf("failed to start HTTP proxy: %w", err)
	}
	p.httpLn = listener

	log.Printf("[HTTP] Proxy listening on %s", p.httpAddr)

	go p.acceptLoop(listener, false)
	return nil
}

// startIPv6 starts the IPv6 listener for fd00::/8 transport interception
func (p *Proxy) startIPv6() error {
	tlsConfig := p.signer.GetTLSConfig()

	listener, err := tls.Listen("tcp6", p.ipv6Addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to start IPv6 listener: %w", err)
	}
	p.ipv6Ln = listener

	log.Printf("[IPv6] Transport listener on %s (for fd00::/8 interception)", p.ipv6Addr)

	go p.acceptLoop(listener, true) // HTTPS mode for transport connections
	return nil
}

// acceptLoop accepts connections and handles them
func (p *Proxy) acceptLoop(listener net.Listener, isHTTPS bool) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-p.stopCh:
				return
			default:
				log.Printf("[PROXY] Accept error: %v", err)
				continue
			}
		}

		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			if isHTTPS {
				p.handleHTTPS(conn)
			} else {
				p.handleHTTP(conn)
			}
		}()
	}
}

// Stop stops the proxy
func (p *Proxy) Stop() {
	close(p.stopCh)
	if p.httpsLn != nil {
		p.httpsLn.Close()
	}
	if p.httpLn != nil {
		p.httpLn.Close()
	}
	if p.ipv6Ln != nil {
		p.ipv6Ln.Close()
	}
	// Close pooled connections
	p.connPoolLock.Lock()
	for addr, conn := range p.connPool {
		conn.Close()
		delete(p.connPool, addr)
	}
	p.connPoolLock.Unlock()
	p.wg.Wait()
}

// getPooledConn gets a connection from the pool or creates a new one
func (p *Proxy) getPooledConn(addr, serverName string) (*tls.Conn, bool, error) {
	p.connPoolLock.Lock()
	if conn, ok := p.connPool[addr]; ok {
		delete(p.connPool, addr)
		p.connPoolLock.Unlock()
		// Check if still usable
		conn.SetDeadline(time.Now().Add(100 * time.Millisecond))
		_, err := conn.Write(nil) // Lightweight check
		conn.SetDeadline(time.Time{})
		if err == nil {
			log.Printf("[HTTPS] Reusing pooled connection to %s", addr)
			return conn, true, nil
		}
		conn.Close() // Stale, close it
	} else {
		p.connPoolLock.Unlock()
	}

	// Create new connection
	realTLSConfig := &tls.Config{
		ServerName:         serverName,
		InsecureSkipVerify: true, // We verify using DNN trust model
	}
	conn, err := tls.Dial("tcp", addr, realTLSConfig)
	if err != nil {
		return nil, false, err
	}
	return conn, false, nil
}

// returnPooledConn returns a connection to the pool for reuse
func (p *Proxy) returnPooledConn(addr string, conn *tls.Conn) {
	p.connPoolLock.Lock()
	defer p.connPoolLock.Unlock()
	// Only keep one connection per address
	if existing, ok := p.connPool[addr]; ok {
		existing.Close()
	}
	p.connPool[addr] = conn
}

// handleHTTPS handles HTTPS connections
func (p *Proxy) handleHTTPS(clientConn net.Conn) {
	defer clientConn.Close()

	tlsConn, ok := clientConn.(*tls.Conn)
	if !ok {
		log.Printf("[HTTPS] Not a TLS connection")
		return
	}

	if err := tlsConn.Handshake(); err != nil {
		log.Printf("[HTTPS] Handshake error: %v", err)
		return
	}

	serverName := tlsConn.ConnectionState().ServerName
	if serverName == "" {
		log.Printf("[HTTPS] No SNI provided")
		return
	}

	// Get DNN TLD (for logging)
	dnnTLD := detector.GetTLD(serverName)
	log.Printf("[HTTPS] Connection for: %s (TLD: %s)", serverName, dnnTLD)

	// Extract subdomain if present
	// For "blossom.freakoverse.nabtaabove":
	//   - dnnTLD = "nabtaabove"
	//   - parentName = "freakoverse.nabtaabove"
	//   - subdomain = "blossom"
	var subdomain string
	var parentName string
	parts := strings.Split(strings.ToLower(serverName), ".")
	for i, part := range parts {
		if part == dnnTLD && i > 0 {
			// Found TLD, check for subdomain
			if i >= 2 {
				// Has subdomain: blossom.freakoverse.nabtaabove
				subdomain = parts[0]
				parentName = parts[i-1] + "." + dnnTLD
			} else {
				// No subdomain: freakoverse.nabtaabove
				parentName = serverName
			}
			break
		}
	}
	if parentName == "" {
		parentName = serverName
	}

	// Get cached resolution (keyed by parent name, populated by DNS lookup)
	resolution, ok := p.cache.GetResolution(parentName)
	if !ok {
		// Fallback: resolve now using parent name
		log.Printf("[HTTPS] No cached resolution, resolving %s...", parentName)
		res, err := p.resolver.Resolve(parentName)
		if err != nil {
			log.Printf("[HTTPS] Resolution failed: %v", err)
			return
		}
		certPEM := ""
		if res.Cert != nil {
			certPEM = res.Cert.PEM
		}
		resolution = &mapper.Resolution{IP: res.IP, Port: 443, DeclaredCertPEM: certPEM, SubdomainIPs: res.SubdomainIPs}
	}

	// Determine target IP: use subdomain IP if available, otherwise root IP
	targetIP := resolution.IP
	if subdomain != "" && resolution.SubdomainIPs != nil {
		if subIP, found := resolution.SubdomainIPs[subdomain]; found {
			log.Printf("[HTTPS] Using subdomain IP for '%s': %s (instead of %s)", subdomain, subIP, resolution.IP)
			targetIP = subIP
		}
	}

	// Use HTTPS port (443) if not specified
	port := resolution.Port
	if port == 0 || port == 80 {
		port = 443
	}

	realAddr := fmt.Sprintf("%s:%d", targetIP, port)
	log.Printf("[HTTPS] Connecting to real server: %s", realAddr)

	// Get connection from pool or create new one
	realConn, pooled, err := p.getPooledConn(realAddr, serverName)
	if err != nil {
		log.Printf("[HTTPS] Failed to connect: %v", err)
		return
	}

	// DNN Certificate Verification (only for new connections)
	if !pooled {
		// Get server's certificate as PEM
		serverCerts := realConn.ConnectionState().PeerCertificates
		if len(serverCerts) == 0 {
			log.Printf("[HTTPS] Server returned no certificates")
			realConn.Close()
			return
		}
		serverCertPEM := certToPEM(serverCerts[0])

		// Verify: declared cert matches server cert
		// DNN trust: server cert must EXACTLY match declared cert in 62600
		verifyResult := certverify.VerifyCert(resolution.DeclaredCertPEM, serverCertPEM, serverName)
		if !verifyResult.Valid {
			if errors.Is(verifyResult.Error, certverify.ErrNoDeclaredCert) {
				log.Printf("[HTTPS] ⚠️ No cert declared in 62600 for %s", serverName)
			} else {
				log.Printf("[HTTPS] ⚠️ DNN cert verification FAILED for %s: %v", serverName, verifyResult.Error)
			}
			// CRITICAL: Update cache to mark as NOT verified
			// This ensures signer generates untrusted cert for future connections
			p.cache.SetCertVerified(parentName, false, verifyResult.Error.Error())
			log.Printf("[HTTPS] ❌ Marked %s as NOT verified - future requests will show warning", parentName)
		} else {
			log.Printf("[HTTPS] ✓ DNN cert verified for %s", serverName)
			// Ensure cache is marked as verified (may already be set by DNS)
			p.cache.SetCertVerified(parentName, true, "")
		}
	}

	log.Printf("[HTTPS] Proxying for %s", serverName)

	// Bidirectional copy
	done := make(chan struct{})
	go func() {
		io.Copy(realConn, tlsConn)
		done <- struct{}{}
	}()
	io.Copy(tlsConn, realConn)
	<-done

	// Return connection to pool for reuse (if not closed by server)
	// Note: In practice, you might want more sophisticated health checking
	// p.returnPooledConn(realAddr, realConn)
	realConn.Close() // For now, just close - HTTP/1.1 may not handle reuse well
}

// handleHTTP handles HTTP connections (for port 80 redirects)
func (p *Proxy) handleHTTP(clientConn net.Conn) {
	defer clientConn.Close()

	// Read the first bytes to determine the Host header
	// For simplicity, we'll just proxy to the cached address on port 80
	// A real implementation would parse the HTTP headers

	// Get the remote address - this is always 127.0.0.1 but we need the Host from HTTP
	// For now, we'll read the HTTP request and parse the Host header

	buf := make([]byte, 4096)
	n, err := clientConn.Read(buf)
	if err != nil {
		log.Printf("[HTTP] Read error: %v", err)
		return
	}

	// Simple Host header extraction
	host := extractHostHeader(buf[:n])
	if host == "" {
		log.Printf("[HTTP] No Host header found")
		return
	}

	// Remove port if present
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	dnnTLD := detector.GetTLD(host)
	log.Printf("[HTTP] Connection for: %s (TLD: %s)", host, dnnTLD)

	// Get cached resolution (keyed by full host name including subdomain)
	resolution, ok := p.cache.GetResolution(host)
	if !ok {
		log.Printf("[HTTP] No cached resolution, resolving %s...", host)
		res, err := p.resolver.Resolve(host)
		if err != nil {
			log.Printf("[HTTP] Resolution failed: %v", err)
			return
		}
		resolution = &mapper.Resolution{IP: res.IP, Port: 80}
	}

	port := resolution.Port
	if port == 0 || port == 443 {
		port = 80
	}

	realAddr := fmt.Sprintf("%s:%d", resolution.IP, port)
	log.Printf("[HTTP] Connecting to real server: %s", realAddr)

	realConn, err := net.Dial("tcp", realAddr)
	if err != nil {
		log.Printf("[HTTP] Failed to connect: %v", err)
		return
	}
	defer realConn.Close()

	// Forward the buffered data
	realConn.Write(buf[:n])

	log.Printf("[HTTP] Proxying for %s", host)

	// Bidirectional copy
	go io.Copy(realConn, clientConn)
	io.Copy(clientConn, realConn)
}

// extractHostHeader extracts the Host header from an HTTP request
func extractHostHeader(data []byte) string {
	s := string(data)
	for _, line := range splitLines(s) {
		if len(line) > 6 && (line[:5] == "Host:" || line[:5] == "host:") {
			return trimSpace(line[5:])
		}
	}
	return ""
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			end := i
			if end > start && s[end-1] == '\r' {
				end--
			}
			lines = append(lines, s[start:end])
			start = i + 1
		}
	}
	return lines
}

func trimSpace(s string) string {
	start, end := 0, len(s)
	for start < end && (s[start] == ' ' || s[start] == '\t') {
		start++
	}
	for end > start && (s[end-1] == ' ' || s[end-1] == '\t') {
		end--
	}
	return s[start:end]
}

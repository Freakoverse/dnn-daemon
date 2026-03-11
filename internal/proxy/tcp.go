// Package proxy handles TCP/TLS connection proxying to DNN-resolved destinations.
package proxy

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"dnn-daemon/internal/mapper"
	"dnn-daemon/internal/resolver"
)

// ErrConnectionFailed is returned when connection to the target fails
var ErrConnectionFailed = errors.New("connection to target failed")

// Proxy handles TCP connections to DNN destinations
type Proxy struct {
	cache       *mapper.Cache
	resolver    *resolver.Resolver
	mu          sync.RWMutex
	resCache    map[string]*resolver.Resolution // dnnName -> resolution
	resCacheTTL time.Duration
}

// New creates a new proxy
func New(cache *mapper.Cache, res *resolver.Resolver, ttl time.Duration) *Proxy {
	return &Proxy{
		cache:       cache,
		resolver:    res,
		resCache:    make(map[string]*resolver.Resolution),
		resCacheTTL: ttl,
	}
}

// HandleConnection proxies a TCP connection to its DNN destination
func (p *Proxy) HandleConnection(clientConn net.Conn, dstIP net.IP, dstPort int) error {
	defer clientConn.Close()

	// Look up the DNN name for this IP
	dnnName, ok := p.cache.LookupByIP(dstIP)
	if !ok {
		log.Printf("[Proxy] No DNN mapping found for %s", dstIP)
		return fmt.Errorf("no DNN mapping for %s", dstIP)
	}

	log.Printf("[Proxy] Handling connection to %s (DNN: %s) port %d", dstIP, dnnName, dstPort)

	// Get or resolve the destination
	resolution, err := p.getResolution(dnnName)
	if err != nil {
		log.Printf("[Proxy] Resolution failed for %s: %v", dnnName, err)
		return err
	}

	// Determine target address based on port
	var targetAddr string
	if dstPort == 80 || dstPort == resolution.HTTPPort {
		// HTTP - use plain TCP
		targetAddr = fmt.Sprintf("%s:%d", resolution.IP, resolution.HTTPPort)
		return p.proxyPlain(clientConn, targetAddr)
	} else {
		// HTTPS - use TLS
		targetAddr = fmt.Sprintf("%s:%d", resolution.IP, resolution.Port)
		return p.proxyTLS(clientConn, targetAddr, dnnName, resolution)
	}
}

// getResolution gets a cached resolution or fetches a new one
func (p *Proxy) getResolution(dnnName string) (*resolver.Resolution, error) {
	p.mu.RLock()
	cached, ok := p.resCache[dnnName]
	p.mu.RUnlock()

	if ok && time.Since(cached.ResolvedAt) < p.resCacheTTL {
		return cached, nil
	}

	// Resolve fresh
	res, err := p.resolver.Resolve(dnnName)
	if err != nil {
		return nil, err
	}

	p.mu.Lock()
	p.resCache[dnnName] = res
	p.mu.Unlock()

	return res, nil
}

// proxyPlain proxies a plain TCP connection
func (p *Proxy) proxyPlain(clientConn net.Conn, targetAddr string) error {
	targetConn, err := net.DialTimeout("tcp", targetAddr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}
	defer targetConn.Close()

	return p.copyBidirectional(clientConn, targetConn)
}

// proxyTLS proxies a TLS connection with DNN certificate verification
func (p *Proxy) proxyTLS(clientConn net.Conn, targetAddr, dnnName string, res *resolver.Resolution) error {
	// Create TLS config that accepts self-signed certs
	// We verify the cert ourselves against the DNN-declared cert
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, // We do our own verification
	}

	// Connect to target
	targetConn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		targetAddr,
		tlsConfig,
	)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}
	defer targetConn.Close()

	// Verify the certificate if we have one declared
	if res.Cert != nil && res.Cert.PEM != "" {
		if err := p.verifyCert(targetConn, res.Cert, dnnName); err != nil {
			log.Printf("[Proxy] Certificate verification failed for %s: %v", dnnName, err)
			// Continue anyway - DNN philosophy is to warn but allow
		} else {
			log.Printf("[Proxy] Certificate verified for %s", dnnName)
		}
	}

	return p.copyBidirectional(clientConn, targetConn)
}

// verifyCert verifies the server certificate against the DNN-declared cert
func (p *Proxy) verifyCert(conn *tls.Conn, declaredCert *resolver.CertInfo, dnnName string) error {
	state := conn.ConnectionState()
	if len(state.PeerCertificates) == 0 {
		return errors.New("no server certificate received")
	}

	serverCert := state.PeerCertificates[0]

	// Parse the declared cert
	block, err := decodePEM(declaredCert.PEM)
	if err != nil {
		return fmt.Errorf("failed to decode declared cert: %w", err)
	}

	declaredX509, err := x509.ParseCertificate(block)
	if err != nil {
		return fmt.Errorf("failed to parse declared cert: %w", err)
	}

	// Compare the certificates
	if string(serverCert.Raw) != string(declaredX509.Raw) {
		return errors.New("server certificate does not match DNN-declared certificate")
	}

	// Check SAN for DNN name (soft check - warn only)
	if !containsDNNName(declaredX509, dnnName) {
		log.Printf("[Proxy] Warning: certificate SAN does not contain %s", dnnName)
	}

	return nil
}

// decodePEM decodes a PEM-encoded certificate
func decodePEM(pemData string) ([]byte, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	return block.Bytes, nil
}

// containsDNNName checks if the certificate SAN contains the DNN name
func containsDNNName(cert *x509.Certificate, dnnName string) bool {
	for _, name := range cert.DNSNames {
		if name == dnnName {
			return true
		}
		// Check wildcard
		if len(name) > 2 && name[:2] == "*." {
			suffix := name[1:] // e.g., ".nabceabsurd"
			if len(dnnName) > len(suffix) && dnnName[len(dnnName)-len(suffix):] == suffix {
				return true
			}
		}
	}
	return false
}

// copyBidirectional copies data in both directions between two connections
func (p *Proxy) copyBidirectional(conn1, conn2 net.Conn) error {
	var wg sync.WaitGroup
	wg.Add(2)

	var err1, err2 error

	go func() {
		defer wg.Done()
		_, err1 = io.Copy(conn1, conn2)
	}()

	go func() {
		defer wg.Done()
		_, err2 = io.Copy(conn2, conn1)
	}()

	wg.Wait()

	if err1 != nil {
		return err1
	}
	return err2
}

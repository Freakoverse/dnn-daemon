// Package mapper provides npub to IPv6 address mapping for the DNN daemon.
//
// DNN uses the fd00::/8 IPv6 ULA (Unique Local Address) range to create
// deterministic addresses from npubs. These addresses are never routed on
// the public internet, making them safe for local interception.
package mapper

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"strings"
	"sync"
)

// Prefix is the IPv6 prefix used for DNN addresses (fd00::/8)
var Prefix = net.IP{0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

// ErrInvalidNpub is returned when the npub format is invalid
var ErrInvalidNpub = errors.New("invalid npub format")

// ErrNotDNNAddress is returned when an IPv6 address is not in the fd00::/8 range
var ErrNotDNNAddress = errors.New("not a DNN address (must be in fd00::/8)")

// Resolution stores the actual server address and transport info for a DNN name
type Resolution struct {
	IP              string            // Target IP from A record (@)
	Port            int               // Target port (default 443)
	DeclaredCertPEM string            // Certificate PEM from DNN node (kind 62600)
	CertVerified    bool              // True if server cert was verified against declared cert
	CertChecked     bool              // True if pre-flight verification was attempted
	CertError       string            // If verification failed, the reason
	Npubs           []string          // Server npubs for transport routing
	SubdomainIPs    map[string]string // Subdomain name -> IP (e.g., "blossom" -> "96.9.124.48")
	Transports      struct {
		Relay    []string // Nostr relay URLs
		Tollgate string   // "use" or empty
		Tor      []string // .onion addresses
	}
	InterceptionIPv6 string // fd00::/8 address for this resolution
}

// Cache stores the reverse mapping from IPv6 to DNN name
type Cache struct {
	mu          sync.RWMutex
	ipToName    map[string]string      // IPv6 string -> DNN name
	nameToIP    map[string]net.IP      // DNN name -> IPv6
	resolutions map[string]*Resolution // DNN name -> actual server address
}

// NewCache creates a new mapping cache
func NewCache() *Cache {
	return &Cache{
		ipToName:    make(map[string]string),
		nameToIP:    make(map[string]net.IP),
		resolutions: make(map[string]*Resolution),
	}
}

// NpubToIPv6 converts an npub (or DNN name) to an fd00::/8 IPv6 address.
// The algorithm:
// 1. Hash the input with SHA-256
// 2. Take the first 15 bytes
// 3. Prepend 0xfd to create a 16-byte IPv6 address
func NpubToIPv6(dnnName string) net.IP {
	// Normalize the name
	name := strings.ToLower(strings.TrimSpace(dnnName))

	// Hash the name
	hash := sha256.Sum256([]byte(name))

	// Create IPv6: fd + first 15 bytes of hash
	ip := make(net.IP, 16)
	ip[0] = 0xfd // ULA prefix
	copy(ip[1:], hash[:15])

	return ip
}

// Register adds a DNN name to the cache and returns its IPv6 address
func (c *Cache) Register(dnnName string) net.IP {
	name := strings.ToLower(strings.TrimSpace(dnnName))
	ip := NpubToIPv6(name)

	c.mu.Lock()
	defer c.mu.Unlock()

	c.ipToName[ip.String()] = name
	c.nameToIP[name] = ip

	return ip
}

// LookupByIP returns the DNN name for an IPv6 address
func (c *Cache) LookupByIP(ip net.IP) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	name, ok := c.ipToName[ip.String()]
	return name, ok
}

// LookupByName returns the IPv6 address for a DNN name
func (c *Cache) LookupByName(dnnName string) (net.IP, bool) {
	name := strings.ToLower(strings.TrimSpace(dnnName))

	c.mu.RLock()
	defer c.mu.RUnlock()

	ip, ok := c.nameToIP[name]
	return ip, ok
}

// RegisterWithIP stores a DNN name's real server address and cert for the proxy to use
func (c *Cache) RegisterWithIP(dnnName string, ip string, port int, certPEM string) {
	c.RegisterWithIPAndSubdomains(dnnName, ip, port, certPEM, nil)
}

// RegisterWithIPAndSubdomains stores a DNN name's address, cert, and subdomain IPs
func (c *Cache) RegisterWithIPAndSubdomains(dnnName string, ip string, port int, certPEM string, subdomainIPs map[string]string) {
	name := strings.ToLower(strings.TrimSpace(dnnName))

	c.mu.Lock()
	defer c.mu.Unlock()

	c.resolutions[name] = &Resolution{
		IP:              ip,
		Port:            port,
		DeclaredCertPEM: certPEM,
		SubdomainIPs:    subdomainIPs,
	}
}

// GetResolution returns the real server address for a DNN name
func (c *Cache) GetResolution(dnnName string) (*Resolution, bool) {
	name := strings.ToLower(strings.TrimSpace(dnnName))

	c.mu.RLock()
	defer c.mu.RUnlock()

	res, ok := c.resolutions[name]
	return res, ok
}

// HasDeclaredCert checks if a domain has a declared certificate from the 62600 event.
// Returns true if cert PEM exists AND either verified or not yet checked.
// Returns false if cert PEM is empty OR if pre-flight verification explicitly failed.
func (c *Cache) HasDeclaredCert(dnnName string) bool {
	name := strings.ToLower(strings.TrimSpace(dnnName))

	c.mu.RLock()
	defer c.mu.RUnlock()

	res, ok := c.resolutions[name]
	if !ok || res == nil {
		return false
	}
	if res.DeclaredCertPEM == "" {
		return false
	}
	// If pre-flight was attempted and FAILED, cert is not valid
	if res.CertChecked && !res.CertVerified {
		return false
	}
	return true
}

// IsCertValidForDomain checks if the declared cert is valid for this specific domain.
// Tri-state logic:
// - No declared cert → false (untrusted)
// - Declared cert + preflight FAILED → false (untrusted, mismatch detected)
// - Declared cert + preflight PASSED or not yet checked → true (trusted)
func (c *Cache) IsCertValidForDomain(fullDomain string) bool {
	fullDomain = strings.ToLower(strings.TrimSpace(fullDomain))

	c.mu.RLock()
	defer c.mu.RUnlock()

	parentName := c.findParentDomain(fullDomain)
	if parentName == "" {
		return false
	}

	res, ok := c.resolutions[parentName]
	if !ok || res == nil {
		return false
	}

	if res.DeclaredCertPEM == "" {
		return false
	}
	// If pre-flight was attempted and FAILED, domain is not trusted
	if res.CertChecked && !res.CertVerified {
		return false
	}
	return true
}

// findParentDomain finds the parent domain in resolutions cache
// For "blossom.freakoverse.nabtaabove", returns "freakoverse.nabtaabove" if it exists
func (c *Cache) findParentDomain(fullDomain string) string {
	// First check if exact domain exists
	if _, ok := c.resolutions[fullDomain]; ok {
		return fullDomain
	}

	// Try parent by removing first part
	parts := strings.SplitN(fullDomain, ".", 2)
	if len(parts) == 2 {
		parent := parts[1]
		if _, ok := c.resolutions[parent]; ok {
			return parent
		}
	}

	return ""
}

// NOTE: certCoversDomain function removed - DNN does not require SAN checking

// SetCertVerified updates the certificate verification status for a domain
func (c *Cache) SetCertVerified(dnnName string, verified bool, certError string) {
	name := strings.ToLower(strings.TrimSpace(dnnName))

	c.mu.Lock()
	defer c.mu.Unlock()

	if res, ok := c.resolutions[name]; ok && res != nil {
		res.CertChecked = true
		res.CertVerified = verified
		res.CertError = certError
	}
}

// GetSubdomainIP returns the IP for a specific subdomain of a DNN name
// Example: GetSubdomainIP("freakoverse.nabtaabove", "blossom") -> "96.9.124.48"
func (c *Cache) GetSubdomainIP(dnnName string, subdomain string) (string, bool) {
	name := strings.ToLower(strings.TrimSpace(dnnName))
	subdomain = strings.ToLower(strings.TrimSpace(subdomain))

	c.mu.RLock()
	defer c.mu.RUnlock()

	res, ok := c.resolutions[name]
	if !ok || res == nil || res.SubdomainIPs == nil {
		return "", false
	}

	ip, found := res.SubdomainIPs[subdomain]
	return ip, found
}

// IsDNNAddress checks if an IP is in the fd00::/8 range
func IsDNNAddress(ip net.IP) bool {
	if len(ip) < 16 {
		ip = ip.To16()
	}
	if ip == nil {
		return false
	}
	return ip[0] == 0xfd
}

// ParseNpub extracts the hex pubkey from an npub bech32 string
// For now, we just use the DNN name directly - npub parsing would
// require bech32 decoding which we'll add if needed
func ParseNpub(npub string) (string, error) {
	if strings.HasPrefix(npub, "npub1") && len(npub) == 63 {
		// Valid npub format - return as-is for hashing
		return npub, nil
	}
	// Treat as DNN name (nabceabsurd, n4.8, etc.)
	if len(npub) == 0 {
		return "", ErrInvalidNpub
	}
	return npub, nil
}

// FormatIPv6 returns a human-readable IPv6 string
func FormatIPv6(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

// IPv6ToHex returns the hex representation of an IPv6 address
func IPv6ToHex(ip net.IP) string {
	if len(ip) < 16 {
		ip = ip.To16()
	}
	if ip == nil {
		return ""
	}
	return hex.EncodeToString(ip)
}

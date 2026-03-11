//go:build darwin
// +build darwin

// Package capture provides DNS interception using pf (packet filter) on macOS.
// This approach redirects outbound DNS (UDP 53) to a local DNS server running
// on an alternate port, without modifying system DNS configuration.
package capture

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/miekg/dns"
	"dnn-daemon/internal/detector"
	"dnn-daemon/internal/mapper"
	"dnn-daemon/internal/resolver"
)

const (
	// LocalPort is where our DNS server listens
	LocalPort = 5353
	// UpstreamDNS is the fallback DNS for non-DNN queries
	UpstreamDNS = "8.8.8.8:53"
	// pfAnchor is the pf anchor name for our rules
	pfAnchor = "dnn"
	// pfRulesPath is where we write our pf rules
	pfRulesPath = "/etc/pf.anchors/dnn"
)

// Capture handles DNS interception using pf redirect
type Capture struct {
	cache     *mapper.Cache
	resolver  *resolver.Resolver
	dnsServer *dns.Server
	running   bool
	pfSet     bool
	mu        sync.RWMutex
}

// Config for the capture
type Config struct {
	Cache    *mapper.Cache
	Resolver *resolver.Resolver
}

// New creates a new pf-based DNS capture
func New(cfg *Config) (*Capture, error) {
	c := &Capture{
		cache:    cfg.Cache,
		resolver: cfg.Resolver,
	}

	log.Printf("[Capture] Created pf-based DNS capture (will redirect port 53 -> %d)", LocalPort)
	return c, nil
}

// Start begins DNS interception
func (c *Capture) Start() error {
	c.mu.Lock()
	if c.running {
		c.mu.Unlock()
		return nil
	}
	c.running = true
	c.mu.Unlock()

	// Set up pf redirect
	if err := c.setupPF(); err != nil {
		return fmt.Errorf("failed to set up pf: %w", err)
	}

	// Start local DNS server
	if err := c.startDNSServer(); err != nil {
		c.removePF()
		return fmt.Errorf("failed to start DNS server: %w", err)
	}

	log.Printf("[Capture] Started DNS capture (pf redirect to port %d)", LocalPort)
	return nil
}

// Stop stops DNS interception
func (c *Capture) Stop() {
	c.mu.Lock()
	c.running = false
	c.mu.Unlock()

	if c.dnsServer != nil {
		c.dnsServer.Shutdown()
	}
	c.removePF()

	log.Printf("[Capture] Stopped DNS capture")
}

// setupPF configures packet filter for DNS redirect
func (c *Capture) setupPF() error {
	// Create anchor rules file
	rules := fmt.Sprintf(`# DNN Daemon DNS redirect
rdr pass on lo0 proto udp from any to any port 53 -> 127.0.0.1 port %d
pass out quick proto udp from any to 127.0.0.1 port %d
`, LocalPort, LocalPort)

	if err := os.WriteFile(pfRulesPath, []byte(rules), 0644); err != nil {
		return fmt.Errorf("failed to write pf rules: %w", err)
	}

	// Load the anchor into pf.conf if not already present
	pfConf, _ := os.ReadFile("/etc/pf.conf")
	if !strings.Contains(string(pfConf), "anchor \"dnn\"") {
		// Add our anchor to pf.conf
		newConf := string(pfConf) + "\nanchor \"dnn\"\nload anchor \"dnn\" from \"/etc/pf.anchors/dnn\"\n"
		if err := os.WriteFile("/etc/pf.conf", []byte(newConf), 0644); err != nil {
			return fmt.Errorf("failed to update pf.conf: %w", err)
		}
	}

	// Reload pf
	if err := exec.Command("pfctl", "-f", "/etc/pf.conf").Run(); err != nil {
		log.Printf("[Capture] Warning: pfctl reload failed: %v", err)
	}

	// Enable pf if not already enabled
	exec.Command("pfctl", "-e").Run()

	c.pfSet = true
	log.Printf("[Capture] Added pf redirect: UDP 53 -> %d", LocalPort)
	return nil
}

// removePF removes the pf rules
func (c *Capture) removePF() {
	if !c.pfSet {
		return
	}

	// Remove anchor rules file
	os.Remove(pfRulesPath)

	// Reload pf (will ignore missing anchor file)
	exec.Command("pfctl", "-f", "/etc/pf.conf").Run()

	c.pfSet = false
	log.Printf("[Capture] Removed pf redirect rule")
}

// startDNSServer starts the local DNS server
func (c *Capture) startDNSServer() error {
	handler := dns.HandlerFunc(c.handleDNS)

	c.dnsServer = &dns.Server{
		Addr:    fmt.Sprintf("127.0.0.1:%d", LocalPort),
		Net:     "udp",
		Handler: handler,
	}

	go func() {
		if err := c.dnsServer.ListenAndServe(); err != nil {
			log.Printf("[Capture] DNS server error: %v", err)
		}
	}()

	log.Printf("[Capture] Local DNS server listening on 127.0.0.1:%d", LocalPort)
	return nil
}

// handleDNS processes DNS queries
func (c *Capture) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		return
	}

	qname := r.Question[0].Name
	name := strings.TrimSuffix(qname, ".")

	// Check if DNN
	if detector.IsDNNName(name) {
		log.Printf("[Capture] DNN query: %s", name)
		c.handleDNNQuery(w, r, name)
	} else {
		// Forward to upstream DNS
		c.forwardQuery(w, r)
	}
}

// handleDNNQuery handles DNN name resolution
func (c *Capture) handleDNNQuery(w dns.ResponseWriter, r *dns.Msg, name string) {
	dnnTLD := detector.GetTLD(name)

	// Determine what to resolve:
	// - If name == TLD (e.g., "nabtaabout"), resolve the TLD directly
	// - If name has subdomain (e.g., "asdasd.nabtaabout"), pass the full name
	//   so the node can validate the subdomain against 61600 o-tags
	nameToResolve := name
	if name == dnnTLD {
		nameToResolve = dnnTLD
	} else {
		// Has subdomain - extract just the immediate subdomain + TLD
		parts := strings.Split(strings.ToLower(name), ".")
		for i, part := range parts {
			if part == dnnTLD && i > 0 {
				nameToResolve = parts[i-1] + "." + dnnTLD
				break
			}
		}
	}

	// Resolve via DNN node - pass full name including subdomain
	resolution, err := c.resolver.Resolve(nameToResolve)
	if err != nil {
		log.Printf("[Capture] Failed to resolve %s: %v", nameToResolve, err)
		c.forwardQuery(w, r)
		return
	}

	// Generate interception IPv6
	interceptionIPv6 := mapper.NpubToIPv6(name)
	log.Printf("[Capture] Resolved %s -> %s:%d (IPv6: %s)", nameToResolve, resolution.IP, resolution.Port, interceptionIPv6.String())

	// Cache the resolution
	var certPEM string
	if resolution.Cert != nil {
		certPEM = resolution.Cert.PEM
	}
	c.cache.Register(name)
	c.cache.RegisterWithIP(name, resolution.IP, resolution.Port, certPEM)

	// Build response
	resp := new(dns.Msg)
	resp.SetReply(r)
	resp.Authoritative = true

	qtype := r.Question[0].Qtype

	switch qtype {
	case dns.TypeA:
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: net.ParseIP("127.0.0.1"),
		})
	case dns.TypeAAAA:
		resp.Answer = append(resp.Answer, &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   r.Question[0].Name,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			AAAA: interceptionIPv6,
		})
	default:
		// For other types, forward
		c.forwardQuery(w, r)
		return
	}

	w.WriteMsg(resp)
}

// forwardQuery forwards non-DNN queries to upstream DNS
func (c *Capture) forwardQuery(w dns.ResponseWriter, r *dns.Msg) {
	client := &dns.Client{}
	resp, _, err := client.Exchange(r, UpstreamDNS)
	if err != nil {
		log.Printf("[Capture] Upstream DNS error: %v", err)
		return
	}
	w.WriteMsg(resp)
}

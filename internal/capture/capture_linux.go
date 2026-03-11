//go:build linux
// +build linux

// Package capture provides DNS interception using iptables redirect on Linux.
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
	LocalPort = 15353
	// UpstreamDNS is the fallback DNS for non-DNN queries
	UpstreamDNS = "8.8.8.8:53"
)

// Capture handles DNS interception using iptables redirect
type Capture struct {
	cache       *mapper.Cache
	resolver    *resolver.Resolver
	dnsServer   *dns.Server
	running     bool
	iptablesSet bool
	mu          sync.RWMutex
}

// Config for the capture
type Config struct {
	Cache    *mapper.Cache
	Resolver *resolver.Resolver
}

// New creates a new iptables-based DNS capture
func New(cfg *Config) (*Capture, error) {
	c := &Capture{
		cache:    cfg.Cache,
		resolver: cfg.Resolver,
	}

	log.Printf("[Capture] Created iptables-based DNS capture (will redirect port 53 -> %d)", LocalPort)
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

	// Set up iptables redirect
	if err := c.setupIptables(); err != nil {
		return fmt.Errorf("failed to set up iptables: %w", err)
	}

	// Start local DNS server
	if err := c.startDNSServer(); err != nil {
		c.removeIptables()
		return fmt.Errorf("failed to start DNS server: %w", err)
	}

	log.Printf("[Capture] Started DNS capture (iptables redirect to port %d)", LocalPort)
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
	c.removeIptables()

	log.Printf("[Capture] Stopped DNS capture")
}

// setupIptables adds the redirect rule, excluding the daemon's own traffic
func (c *Capture) setupIptables() error {
	uid := fmt.Sprintf("%d", os.Getuid())

	// Rule 1: RETURN (skip redirect) for daemon's own DNS queries
	// Prevents loop: daemon -> 8.8.8.8:53 -> iptables -> back to daemon
	cmd := exec.Command("iptables", "-t", "nat", "-A", "OUTPUT",
		"-p", "udp", "--dport", "53",
		"-m", "owner", "--uid-owner", uid,
		"-j", "RETURN")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("iptables RETURN rule failed: %w (try running with sudo/root)", err)
	}

	// Rule 2: Redirect all OTHER outbound UDP 53 to our local DNS server
	cmd = exec.Command("iptables", "-t", "nat", "-A", "OUTPUT",
		"-p", "udp", "--dport", "53",
		"-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", LocalPort))
	if err := cmd.Run(); err != nil {
		// Clean up the RETURN rule on failure
		exec.Command("iptables", "-t", "nat", "-D", "OUTPUT",
			"-p", "udp", "--dport", "53",
			"-m", "owner", "--uid-owner", uid,
			"-j", "RETURN").Run()
		return fmt.Errorf("iptables REDIRECT rule failed: %w", err)
	}

	c.iptablesSet = true
	log.Printf("[Capture] Added iptables redirect: UDP 53 -> %d (excluding UID %s)", LocalPort, uid)
	return nil
}

// removeIptables removes both redirect rules
func (c *Capture) removeIptables() {
	if !c.iptablesSet {
		return
	}

	uid := fmt.Sprintf("%d", os.Getuid())

	// Remove REDIRECT rule
	exec.Command("iptables", "-t", "nat", "-D", "OUTPUT",
		"-p", "udp", "--dport", "53",
		"-j", "REDIRECT", "--to-port", fmt.Sprintf("%d", LocalPort)).Run()

	// Remove RETURN rule
	exec.Command("iptables", "-t", "nat", "-D", "OUTPUT",
		"-p", "udp", "--dport", "53",
		"-m", "owner", "--uid-owner", uid,
		"-j", "RETURN").Run()

	c.iptablesSet = false
	log.Printf("[Capture] Removed iptables redirect rules")
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

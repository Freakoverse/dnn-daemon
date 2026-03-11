// Package resolver handles DNN name resolution via DNN node APIs.
package resolver

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/nbd-wtf/go-nostr"
)

// ErrNotFound is returned when a DNN name cannot be resolved
var ErrNotFound = errors.New("DNN name not found")

// ErrAllNodesFailed is returned when all DNN nodes fail
var ErrAllNodesFailed = errors.New("all DNN nodes failed")

// maxNodesPerSet is the number of nodes queried in parallel per attempt
const maxNodesPerSet = 3

// maxRetrySets is the maximum number of sets to try before giving up
const maxRetrySets = 3

// parallelTimeout is the timeout for all parallel queries in a single set
const parallelTimeout = 2 * time.Second

// resolveResult holds a single node's response for comparison
type resolveResult struct {
	resolution  *Resolution
	connEvent   *nostr.Event // Raw signed connection event for verification
	domainFound bool         // Whether the requested domain was found in the connection content
	nodeURL     string
	err         error
}

// Resolve resolves a DNN name to its connection information.
// Queries up to 3 random nodes in parallel, verifies Nostr signatures,
// and picks the freshest valid response. Retries with new sets on failure.
func (r *Resolver) Resolve(dnnName string) (*Resolution, error) {
	r.mu.RLock()
	allNodes := make([]string, len(r.nodes))
	copy(allNodes, r.nodes)
	r.mu.RUnlock()

	if len(allNodes) == 0 {
		return nil, ErrAllNodesFailed
	}

	// Shuffle nodes for random selection
	rand.Shuffle(len(allNodes), func(i, j int) {
		allNodes[i], allNodes[j] = allNodes[j], allNodes[i]
	})

	// Try sets of up to maxNodesPerSet nodes
	for set := 0; set < maxRetrySets; set++ {
		startIdx := set * maxNodesPerSet
		if startIdx >= len(allNodes) {
			break // No more nodes available
		}

		endIdx := startIdx + maxNodesPerSet
		if endIdx > len(allNodes) {
			endIdx = len(allNodes)
		}

		setNodes := allNodes[startIdx:endIdx]

		// Query all nodes in this set in parallel
		results := r.queryNodesParallel(setNodes, dnnName)

		// Pick the best valid response
		best := r.pickBestResult(results)
		if best != nil {
			return best, nil
		}

		// All nodes in this set failed — try next set
		log.Printf("[Resolver] Set %d failed (%d nodes), trying next set...", set+1, len(setNodes))
	}

	return nil, ErrAllNodesFailed
}

// queryNodesParallel queries multiple nodes concurrently and returns all results
func (r *Resolver) queryNodesParallel(nodes []string, dnnName string) []resolveResult {
	var wg sync.WaitGroup
	results := make([]resolveResult, len(nodes))

	for i, node := range nodes {
		wg.Add(1)
		go func(idx int, nodeURL string) {
			defer wg.Done()
			res, connEvent, df, err := r.resolveFromNode(nodeURL, dnnName)
			results[idx] = resolveResult{
				resolution:  res,
				connEvent:   connEvent,
				domainFound: df,
				nodeURL:     nodeURL,
				err:         err,
			}
		}(i, node)
	}

	// Wait with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// All nodes responded
	case <-time.After(parallelTimeout):
		log.Printf("[Resolver] Timeout waiting for %d nodes", len(nodes))
		// Return whatever results we have so far
	}

	return results
}

// pickBestResult selects the best valid response from parallel query results.
// Verifies signatures, checks pubkey consistency, and picks the newest created_at.
func (r *Resolver) pickBestResult(results []resolveResult) *Resolution {
	type validResult struct {
		resolution  *Resolution
		createdAt   int64
		pubkey      string
		nodeURL     string
		domainFound bool
	}

	var valid []validResult

	for _, res := range results {
		if res.err != nil || res.resolution == nil {
			continue
		}

		// If we have a raw connection event, verify its signature
		if res.connEvent != nil {
			ok, err := res.connEvent.CheckSignature()
			if err != nil || !ok {
				log.Printf("[Resolver] ⚠️ Signature verification FAILED for node %s (event %s): %v",
					res.nodeURL, res.connEvent.ID[:16], err)
				continue // Skip this response — invalid signature
			}

			valid = append(valid, validResult{
				resolution:  res.resolution,
				createdAt:   int64(res.connEvent.CreatedAt),
				pubkey:      res.connEvent.PubKey,
				nodeURL:     res.nodeURL,
				domainFound: res.domainFound,
			})
		} else {
			// No raw event (older node version) — accept but with timestamp 0
			// so it loses to any verified response
			valid = append(valid, validResult{
				resolution:  res.resolution,
				createdAt:   0,
				pubkey:      res.resolution.Pubkey,
				nodeURL:     res.nodeURL,
				domainFound: res.domainFound,
			})
		}
	}

	if len(valid) == 0 {
		return nil
	}

	// Check pubkey consistency — all valid responses should have the same pubkey
	refPubkey := valid[0].pubkey
	for _, v := range valid[1:] {
		if v.pubkey != "" && refPubkey != "" && v.pubkey != refPubkey {
			log.Printf("[Resolver] ⚠️ Pubkey mismatch! Node %s has pubkey %s, expected %s — skipping inconsistent results",
				v.nodeURL, v.pubkey[:16], refPubkey[:16])
			// Don't return any result when there's a pubkey mismatch — something is wrong
			return nil
		}
	}

	// Pick the response with the newest created_at
	best := valid[0]
	for _, v := range valid[1:] {
		if v.createdAt > best.createdAt {
			best = v
		}
	}

	if len(valid) > 1 {
		log.Printf("[Resolver] ✓ Picked freshest response from %s (created_at=%d, domain_found=%v, %d/%d nodes valid)",
			best.nodeURL, best.createdAt, best.domainFound, len(valid), len(results))
	}

	// If the freshest response says the domain wasn't found, the domain was removed
	if !best.domainFound {
		log.Printf("[Resolver] Freshest response (created_at=%d) says domain not found — domain was removed", best.createdAt)
		return nil
	}

	return best.resolution
}

// Resolution holds the result of resolving a DNN name
type Resolution struct {
	Pubkey     string                 `json:"pubkey"`      // Owner's npub
	Name       string                 `json:"name"`        // Resolved name
	IP         string                 `json:"ip"`          // Target IP address (root @)
	Port       int                    `json:"port"`        // Target port (default 443)
	HTTPPort   int                    `json:"http_port"`   // HTTP port (default 80)
	Cert       *CertInfo              `json:"cert"`        // Certificate info (if present)
	Connection map[string]interface{} `json:"connection"`  // Raw connection data
	ResolvedAt time.Time              `json:"resolved_at"` // When this was resolved

	// Subdomain routing
	SubdomainIPs map[string]string `json:"subdomain_ips"` // Subdomain name -> IP (e.g., "blossom" -> "96.9.124.48")

	// Transport-first fields (NIP-DN)
	Transports       TransportConfig `json:"transports"`        // Transport options
	InterceptionIPv6 string          `json:"interception_ipv6"` // fd00::/8 address for interception
	Npubs            []string        `json:"npub"`              // Server npubs for transport routing
}

// TransportConfig holds transport options from 62600 connection event
type TransportConfig struct {
	Relay    []string `json:"relay"`    // Nostr relay URLs ["wss://relay.example.com"]
	Tollgate string   `json:"tollgate"` // "use" or empty
}

// HasTransports returns true if any transport is configured
func (r *Resolution) HasTransports() bool {
	return len(r.Transports.Relay) > 0 || r.Transports.Tollgate == "use"
}

// CertInfo holds certificate information from the connection event
type CertInfo struct {
	PEM       string `json:"pem"`
	Signature string `json:"cert_signature,omitempty"`
	Expires   int64  `json:"expires,omitempty"`
}

// Resolver resolves DNN names via DNN node APIs
type Resolver struct {
	nodes       []string
	client      *http.Client
	currentNode int
	mu          sync.RWMutex
}

// New creates a new resolver with the given DNN node URLs
func New(nodes []string) *Resolver {
	return &Resolver{
		nodes: nodes,
		client: &http.Client{
			Timeout: 5 * time.Second, // Per-node timeout (parallelTimeout handles overall)
		},
		currentNode: 0,
	}
}

// UpdateNodes updates the list of DNN nodes (called by peer discovery)
func (r *Resolver) UpdateNodes(nodes []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.nodes = nodes
	// Reset current node if it's out of bounds
	if r.currentNode >= len(nodes) {
		r.currentNode = 0
	}
}

// resolveFromNode attempts resolution from a single node.
// Returns the Resolution, raw signed connection event, whether the domain was found, and any error.
func (r *Resolver) resolveFromNode(nodeURL, dnnName string) (*Resolution, *nostr.Event, bool, error) {
	url := fmt.Sprintf("%s/dnn/resolve/%s", nodeURL, dnnName)

	resp, err := r.client.Get(url)
	if err != nil {
		return nil, nil, false, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil, false, ErrNotFound
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, nil, false, fmt.Errorf("node returned status %d: %s", resp.StatusCode, string(body))
	}

	// Parse the response
	var rawResp struct {
		Pubkey     string                 `json:"pubkey"`
		Name       string                 `json:"name"`
		Encoded    string                 `json:"encoded"`
		Connection map[string]interface{} `json:"connection"`
		DomainFound *bool                 `json:"domain_found"` // nil if not present (older node)
		// Raw signed connection event for signature verification
		ConnectionEventRaw *struct {
			ID        string          `json:"id"`
			Pubkey    string          `json:"pubkey"`
			Sig       string          `json:"sig"`
			CreatedAt int64           `json:"created_at"`
			Kind      int             `json:"kind"`
			Content   string          `json:"content"`
			Tags      nostr.Tags      `json:"tags"`
		} `json:"connection_event_raw"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&rawResp); err != nil {
		return nil, nil, false, fmt.Errorf("failed to decode response: %w", err)
	}

	// Extract IP and port from connection records
	ip, httpPort, httpsPort, subdomainIPs := extractConnectionInfo(rawResp.Connection)

	// Extract certificate if present
	cert := extractCert(rawResp.Connection)

	// Extract transport info (NIP-DN)
	transports, ipv6, npubs := extractTransportInfo(rawResp.Connection)

	resolution := &Resolution{
		Pubkey:           rawResp.Pubkey,
		Name:             rawResp.Name,
		IP:               ip,
		Port:             httpsPort,
		HTTPPort:         httpPort,
		Cert:             cert,
		Connection:       rawResp.Connection,
		ResolvedAt:       time.Now(),
		SubdomainIPs:     subdomainIPs,
		Transports:       transports,
		InterceptionIPv6: ipv6,
		Npubs:            npubs,
	}

	// Reconstruct the raw Nostr event for signature verification
	var connEvent *nostr.Event
	if rawResp.ConnectionEventRaw != nil {
		connEvent = &nostr.Event{
			ID:        rawResp.ConnectionEventRaw.ID,
			PubKey:    rawResp.ConnectionEventRaw.Pubkey,
			Sig:       rawResp.ConnectionEventRaw.Sig,
			CreatedAt: nostr.Timestamp(rawResp.ConnectionEventRaw.CreatedAt),
			Kind:      rawResp.ConnectionEventRaw.Kind,
			Content:   rawResp.ConnectionEventRaw.Content,
			Tags:      rawResp.ConnectionEventRaw.Tags,
		}
	}

	// Determine if the domain was found (default true for backwards compatibility)
	domainFound := true
	if rawResp.DomainFound != nil {
		domainFound = *rawResp.DomainFound
	}

	return resolution, connEvent, domainFound, nil
}

// extractConnectionInfo extracts IP and ports from connection data
// Returns root IP (@), ports, and a map of subdomain -> IP
func extractConnectionInfo(conn map[string]interface{}) (ip string, httpPort, httpsPort int, subdomainIPs map[string]string) {
	httpPort = 80
	httpsPort = 443
	subdomainIPs = make(map[string]string)

	records, ok := conn["records"].([]interface{})
	if !ok {
		return "", 0, 0, subdomainIPs
	}

	for _, r := range records {
		record, ok := r.(map[string]interface{})
		if !ok {
			continue
		}

		recordType, _ := record["type"].(string)
		recordName, _ := record["name"].(string)

		switch recordType {
		case "A":
			// Extract IP from A record
			var recordIP string
			if values, ok := record["values"].([]interface{}); ok && len(values) > 0 {
				recordIP, _ = values[0].(string)
			} else if val, ok := record["value"].(string); ok {
				recordIP = val
			}

			if recordIP != "" {
				if recordName == "@" || recordName == "" {
					// Root domain A record
					ip = recordIP
				} else {
					// Subdomain A record (e.g., "blossom" -> "96.9.124.48")
					subdomainIPs[recordName] = recordIP
				}
			}
		case "SRV":
			// Extract ports from SRV records
			name, _ := record["name"].(string)
			port, _ := record["port"].(float64)
			if name == "_http._tcp" {
				httpPort = int(port)
			} else if name == "_https._tcp" {
				httpsPort = int(port)
			}
		}
	}

	return ip, httpPort, httpsPort, subdomainIPs
}

// extractTransportInfo extracts transport configuration from connection data (NIP-DN)
func extractTransportInfo(conn map[string]interface{}) (transports TransportConfig, ipv6 string, npubs []string) {
	// Connection data comes from the node API as a flattened ParsedConnection struct
	// Fields (interception_ipv6, npub, transports) are at the top level

	// Extract interception_ipv6
	if v, ok := conn["interception_ipv6"].(string); ok {
		ipv6 = v
	}

	// Extract npub array
	if npubArr, ok := conn["npub"].([]interface{}); ok {
		for _, n := range npubArr {
			if s, ok := n.(string); ok {
				npubs = append(npubs, s)
			}
		}
	}

	// Extract transports object
	if transportObj, ok := conn["transports"].(map[string]interface{}); ok {
		// Extract relay URLs
		if relayArr, ok := transportObj["relay"].([]interface{}); ok {
			for _, r := range relayArr {
				if s, ok := r.(string); ok {
					transports.Relay = append(transports.Relay, s)
				}
			}
		}

		// Extract tollgate
		if tg, ok := transportObj["tollgate"].(string); ok {
			transports.Tollgate = tg
		}
	}

	return transports, ipv6, npubs
}

// extractCert extracts certificate info from connection data
func extractCert(conn map[string]interface{}) *CertInfo {
	// Connection data comes from the node API as a flattened ParsedConnection struct
	// The cert field is at the top level
	if certData, ok := conn["cert"].(map[string]interface{}); ok {
		return parseCertData(certData)
	}

	return nil
}

func parseCertData(data map[string]interface{}) *CertInfo {
	cert := &CertInfo{}

	if pem, ok := data["pem"].(string); ok {
		cert.PEM = pem
	}
	if sig, ok := data["cert_signature"].(string); ok {
		cert.Signature = sig
	}
	if exp, ok := data["expires"].(float64); ok {
		cert.Expires = int64(exp)
	}

	if cert.PEM == "" {
		return nil
	}

	return cert
}

// HealthCheck checks if a node is healthy
func (r *Resolver) HealthCheck(nodeURL string) bool {
	url := fmt.Sprintf("%s/dnn/resolve/n1.1", nodeURL)

	resp, err := r.client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// 200 or 404 means the node is working
	return resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound
}

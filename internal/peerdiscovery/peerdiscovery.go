// Package peerdiscovery implements self-healing DNN node discovery.
// It crawls known nodes to discover peers and maintains a pool of healthy nodes.
package peerdiscovery

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	// MaxPoolSize is the maximum number of nodes to maintain in the pool
	MaxPoolSize = 21
	// RefreshInterval is how often to refresh the pool (24 hours)
	RefreshInterval = 24 * time.Hour
	// HealthCheckTimeout is the timeout for health checks
	HealthCheckTimeout = 10 * time.Second
	// CrawlTimeout is the timeout for crawling a node
	CrawlTimeout = 15 * time.Second
)

// Discovery manages DNN node discovery and maintains a healthy pool
type Discovery struct {
	seedNodes []string     // Initial nodes from config
	pool      []string     // Current healthy node pool
	poolMu    sync.RWMutex // Pool lock
	seen      map[string]bool
	seenMu    sync.Mutex
	client    *http.Client
	stopCh    chan struct{}
	wg        sync.WaitGroup
}

// New creates a new Discovery with seed nodes
func New(seedNodes []string) *Discovery {
	return &Discovery{
		seedNodes: seedNodes,
		pool:      make([]string, 0, MaxPoolSize),
		seen:      make(map[string]bool),
		client: &http.Client{
			Timeout: CrawlTimeout,
		},
		stopCh: make(chan struct{}),
	}
}

// Start begins the discovery process and periodic refresh
func (d *Discovery) Start() {
	log.Printf("[PeerDiscovery] Starting with %d seed nodes", len(d.seedNodes))

	// Initial discovery
	d.refreshPool()

	// Start background refresh
	d.wg.Add(1)
	go d.refreshLoop()
}

// Stop stops the discovery process
func (d *Discovery) Stop() {
	close(d.stopCh)
	d.wg.Wait()
	log.Printf("[PeerDiscovery] Stopped")
}

// GetNodes returns the current pool of healthy nodes
func (d *Discovery) GetNodes() []string {
	d.poolMu.RLock()
	defer d.poolMu.RUnlock()

	// Return seed nodes + discovered nodes
	result := make([]string, 0, len(d.seedNodes)+len(d.pool))
	result = append(result, d.seedNodes...)
	for _, node := range d.pool {
		// Don't duplicate seed nodes
		if !d.isSeedNode(node) {
			result = append(result, node)
		}
	}
	return result
}

// isSeedNode checks if a node is a seed node
func (d *Discovery) isSeedNode(node string) bool {
	for _, seed := range d.seedNodes {
		if normalizeURL(seed) == normalizeURL(node) {
			return true
		}
	}
	return false
}

// refreshLoop runs the periodic refresh
func (d *Discovery) refreshLoop() {
	defer d.wg.Done()

	ticker := time.NewTicker(RefreshInterval)
	defer ticker.Stop()

	for {
		select {
		case <-d.stopCh:
			return
		case <-ticker.C:
			log.Printf("[PeerDiscovery] Starting 24h refresh")
			d.refreshPool()
		}
	}
}

// refreshPool crawls all known nodes and refreshes the pool
func (d *Discovery) refreshPool() {
	// Reset seen set for fresh crawl
	d.seenMu.Lock()
	d.seen = make(map[string]bool)
	d.seenMu.Unlock()

	// Start with seed nodes
	nodesToCrawl := make([]string, len(d.seedNodes))
	copy(nodesToCrawl, d.seedNodes)

	// Also include current pool
	d.poolMu.RLock()
	nodesToCrawl = append(nodesToCrawl, d.pool...)
	d.poolMu.RUnlock()

	// Crawl and discover new nodes
	var newPool []string
	crawled := 0

	for len(nodesToCrawl) > 0 && len(newPool) < MaxPoolSize {
		// Take next node to crawl
		node := nodesToCrawl[0]
		nodesToCrawl = nodesToCrawl[1:]

		// Skip if already seen
		d.seenMu.Lock()
		if d.seen[normalizeURL(node)] {
			d.seenMu.Unlock()
			continue
		}
		d.seen[normalizeURL(node)] = true
		d.seenMu.Unlock()

		// Health check first
		if !d.healthCheck(node) {
			continue
		}

		// Add to pool if healthy and not a seed
		if !d.isSeedNode(node) && len(newPool) < MaxPoolSize {
			newPool = append(newPool, node)
		}

		// Crawl for more peers
		peers := d.crawlNode(node)
		crawled++

		// Add new peers to crawl queue
		for _, peer := range peers {
			d.seenMu.Lock()
			if !d.seen[normalizeURL(peer)] {
				nodesToCrawl = append(nodesToCrawl, peer)
			}
			d.seenMu.Unlock()
		}

		// Don't crawl too many nodes
		if crawled > 50 {
			break
		}
	}

	// Update pool
	d.poolMu.Lock()
	d.pool = newPool
	d.poolMu.Unlock()

	log.Printf("[PeerDiscovery] Pool refreshed: %d discovered nodes (+ %d seed nodes)",
		len(newPool), len(d.seedNodes))
}

// crawlNode fetches peers from a single node
func (d *Discovery) crawlNode(nodeURL string) []string {
	var allPeers []string

	// Fetch /dnn/peers
	peers1 := d.fetchPeers(nodeURL, "/dnn/peers")
	allPeers = append(allPeers, peers1...)

	// Fetch /dnn/discovered-peers
	peers2 := d.fetchPeers(nodeURL, "/dnn/discovered-peers")
	allPeers = append(allPeers, peers2...)

	if len(allPeers) > 0 {
		log.Printf("[PeerDiscovery] Found %d peers from %s", len(allPeers), nodeURL)
	}

	return allPeers
}

// fetchPeers fetches a peer list from a specific endpoint
func (d *Discovery) fetchPeers(nodeURL, endpoint string) []string {
	url := strings.TrimSuffix(nodeURL, "/") + endpoint

	resp, err := d.client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}

	// Try to parse as JSON array
	var peers []string
	if err := json.Unmarshal(body, &peers); err != nil {
		// Try as object with "peers" field
		var obj struct {
			Peers []string `json:"peers"`
		}
		if err := json.Unmarshal(body, &obj); err != nil {
			return nil
		}
		peers = obj.Peers
	}

	return peers
}

// healthCheck checks if a node is healthy
func (d *Discovery) healthCheck(nodeURL string) bool {
	client := &http.Client{
		Timeout: HealthCheckTimeout,
	}

	// Try /dnn/health first
	url := strings.TrimSuffix(nodeURL, "/") + "/dnn/health"
	resp, err := client.Get(url)
	if err == nil {
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return true
		}
	}

	// Fallback: try /dnn/resolve with a test query
	url = strings.TrimSuffix(nodeURL, "/") + "/dnn/resolve/nabtaabove"
	resp, err = client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// normalizeURL normalizes a URL for comparison
func normalizeURL(url string) string {
	url = strings.TrimSpace(url)
	url = strings.TrimSuffix(url, "/")
	url = strings.ToLower(url)
	return url
}

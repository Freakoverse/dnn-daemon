// Package transports provides transport handlers for DNN transport-first resolution.
// These transports allow connecting to servers without relying on IP addresses.
package transports

import (
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"dnn-daemon/internal/resolver"
)

// Transport defines the interface for DNN transport methods
type Transport interface {
	// Connect establishes a connection via this transport
	Connect() (net.Conn, error)
	// Available checks if this transport can be used
	Available() bool
	// Name returns the transport name for logging
	Name() string
}

// ErrNoTransportAvailable is returned when all transports fail
var ErrNoTransportAvailable = errors.New("no transport available")

// TryTransports attempts each configured transport in order, falling back to IP
func TryTransports(res *resolver.Resolution, timeout time.Duration) (net.Conn, error) {
	if res == nil {
		return nil, errors.New("nil resolution")
	}

	// Try relay transport first
	if len(res.Transports.Relay) > 0 && len(res.Npubs) > 0 {
		log.Printf("[Transport] Trying relay transport (%d relays, %d npubs)", len(res.Transports.Relay), len(res.Npubs))
		conn, err := RelayConnect(res.Transports.Relay, res.Npubs, timeout)
		if err == nil {
			log.Printf("[Transport] ✓ Connected via relay")
			return conn, nil
		}
		log.Printf("[Transport] Relay failed: %v", err)
	}

	// Try tollgate transport
	if res.Transports.Tollgate == "use" && len(res.Npubs) > 0 {
		log.Printf("[Transport] Trying tollgate transport (%d npubs)", len(res.Npubs))
		conn, err := TollgateConnect(res.Npubs, timeout)
		if err == nil {
			log.Printf("[Transport] ✓ Connected via tollgate")
			return conn, nil
		}
		log.Printf("[Transport] Tollgate failed: %v", err)
	}

	// Fallback to direct IP connection
	if res.IP != "" {
		addr := fmt.Sprintf("%s:%d", res.IP, res.Port)
		log.Printf("[Transport] Falling back to direct IP: %s", addr)
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err == nil {
			log.Printf("[Transport] ✓ Connected via direct IP")
			return conn, nil
		}
		log.Printf("[Transport] Direct IP failed: %v", err)
	}

	return nil, ErrNoTransportAvailable
}

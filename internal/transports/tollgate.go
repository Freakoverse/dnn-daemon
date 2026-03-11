package transports

import (
	"errors"
	"net"
	"time"
)

// TollgateConnect attempts to connect via TollGate mesh network
// This is a stub - will be integrated when TollGate provides the routing API
func TollgateConnect(npubs []string, timeout time.Duration) (net.Conn, error) {
	// TODO: Integrate with TollGate when available
	// 1. Look up server npub in TollGate mesh
	// 2. Route connection through TollGate network
	// 3. Return as virtual connection
	return nil, errors.New("tollgate transport not yet implemented")
}

package certverify

import (
	"crypto/tls"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"time"
)

const (
	// PreflightTimeout is how long we wait for the TLS handshake
	PreflightTimeout = 3 * time.Second
)

// PreflightResult contains the result of a pre-flight cert check
type PreflightResult struct {
	Verified  bool
	Error     string
	ServerPEM string // The server's actual cert PEM (for logging/debugging)
}

// PreflightVerify does a quick TLS handshake to the target server and verifies
// its certificate against the declared PEM from the 62600 connection event.
// This is called during DNS resolution so the result is available before the
// browser connects.
func PreflightVerify(ip string, port int, declaredPEM string, dnnName string) *PreflightResult {
	result := &PreflightResult{}

	if declaredPEM == "" {
		result.Error = "no declared cert"
		return result
	}

	// Connect to the real server with TLS (skip verification since we do our own)
	addr := fmt.Sprintf("%s:%d", ip, port)
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: PreflightTimeout},
		"tcp",
		addr,
		&tls.Config{
			InsecureSkipVerify: true, // We verify against 62600 PEM, not CA chain
			ServerName:         dnnName,
		},
	)
	if err != nil {
		result.Error = fmt.Sprintf("TLS dial failed: %v", err)
		log.Printf("[Preflight] Failed to connect to %s for %s: %v", addr, dnnName, err)
		return result
	}
	defer conn.Close()

	// Get the server's certificate
	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		result.Error = "server returned no certificates"
		return result
	}

	// Encode the server's leaf cert to PEM
	serverPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certs[0].Raw,
	}))
	result.ServerPEM = serverPEM

	// Compare against declared cert using existing verification logic
	verifyResult := VerifyCert(declaredPEM, serverPEM, dnnName)
	if verifyResult.Valid {
		result.Verified = true
		log.Printf("[Preflight] ✅ Cert verified for %s (PEM match)", dnnName)
	} else {
		result.Error = verifyResult.Error.Error()
		log.Printf("[Preflight] ❌ Cert MISMATCH for %s: %v", dnnName, verifyResult.Error)
	}

	return result
}

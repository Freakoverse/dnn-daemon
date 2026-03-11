// Package certverify implements DNN certificate verification logic.
//
// The verification process:
// 1. Get declared cert from DNN node (kind 62600 event)
// 2. Get actual cert from server during TLS handshake
// 3. Compare: declared cert == server cert
//
// NOTE: Unlike traditional PKI, DNN does NOT check if the cert's SAN matches
// the domain. DNN trust comes from the Nostr 62600 event, not the certificate.
// If the server presents the exact cert declared in the event, it's trusted.
//
// If verification fails, the daemon should NOT sign the cert with the local CA.
package certverify

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

var (
	ErrNoDeclaredCert = errors.New("no certificate declared in DNN connection event")
	ErrCertMismatch   = errors.New("server certificate does not match declared certificate")
	ErrNoDNNIDInCert  = errors.New("no DNN ID found in certificate SAN")
	ErrDNNIDMismatch  = errors.New("certificate DNN ID does not match visited domain")
	ErrInvalidCert    = errors.New("invalid certificate format")
)

// VerificationResult contains the result of certificate verification
type VerificationResult struct {
	Valid      bool
	Error      error
	CertDNNID  string // DNN ID found in certificate
	VisitedDNN string // DNN name that was visited
}

// VerifyCert verifies that a server's certificate matches the declared certificate
// declaredPEM: certificate PEM from DNN node (kind 62600)
// serverPEM: certificate PEM from actual TLS handshake
// dnnName: the full DNN domain being visited (for logging purposes)
//
// DNN Verification Logic:
// - Server certificate must EXACTLY match the declared certificate in 62600
// - SAN checking is NOT required - DNN trust comes from the Nostr event, not the cert's SAN
// - If the owner declares "use this cert", that's the authorization
func VerifyCert(declaredPEM, serverPEM, dnnName string) *VerificationResult {
	result := &VerificationResult{
		Valid:      false,
		VisitedDNN: strings.ToLower(dnnName),
	}

	// Step 1: Must have a declared cert
	if declaredPEM == "" {
		result.Error = ErrNoDeclaredCert
		return result
	}

	// Step 2: Compare declared cert with server cert
	if serverPEM == "" {
		result.Error = fmt.Errorf("%w: no server certificate provided", ErrInvalidCert)
		return result
	}

	if !compareCerts(declaredPEM, serverPEM) {
		result.Error = ErrCertMismatch
		return result
	}

	// Extract DNN ID for logging purposes (optional, may be empty)
	result.CertDNNID, _ = extractDNNIDFromCert(serverPEM)

	// Cert matches - that's all we need for DNN trust!
	result.Valid = true
	return result
}

// compareCerts compares two PEM-encoded certificates for equality
func compareCerts(pem1, pem2 string) bool {
	// Normalize and compare
	n1 := normalizePEM(pem1)
	n2 := normalizePEM(pem2)
	return n1 == n2
}

// normalizePEM removes whitespace for comparison
func normalizePEM(pemStr string) string {
	// Remove all whitespace
	return strings.ReplaceAll(
		strings.ReplaceAll(
			strings.ReplaceAll(pemStr, "\r", ""),
			"\n", ""),
		" ", "")
}

// certCoversDomain checks if the certificate's SAN covers the visited domain
// This matches traditional TLS behavior:
// - Exact match: cert has "blossom.freakoverse.nabtaabove"
// - Wildcard match: cert has "*.freakoverse.nabtaabove" covers "blossom.freakoverse.nabtaabove"
// - Parent match: cert has "freakoverse.nabtaabove" covers "freakoverse.nabtaabove" (not subdomains)
func certCoversDomain(pemStr, visitedDomain string) bool {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return false
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false
	}

	visited := strings.ToLower(visitedDomain)

	// Check each SAN DNS name
	for _, sanName := range cert.DNSNames {
		san := strings.ToLower(sanName)

		// Exact match
		if visited == san {
			return true
		}

		// Wildcard match: *.freakoverse.nabtaabove matches blossom.freakoverse.nabtaabove
		// Wildcard only matches ONE level (standard TLS behavior)
		if strings.HasPrefix(san, "*.") {
			// Remove "*" to get ".freakoverse.nabtaabove"
			wildcardSuffix := san[1:]
			// Check if visited ends with the wildcard suffix
			// AND that there's exactly one level before it
			if strings.HasSuffix(visited, wildcardSuffix) {
				// Count dots in the prefix part
				prefix := visited[:len(visited)-len(wildcardSuffix)]
				// Prefix should not contain any dots (single level only)
				if !strings.Contains(prefix, ".") && prefix != "" {
					return true
				}
			}
		}
	}

	// Also check Common Name as fallback (older certs)
	cn := strings.ToLower(cert.Subject.CommonName)
	if cn != "" {
		if visited == cn {
			return true
		}
		if strings.HasPrefix(cn, "*.") {
			wildcardSuffix := cn[1:]
			if strings.HasSuffix(visited, wildcardSuffix) {
				prefix := visited[:len(visited)-len(wildcardSuffix)]
				if !strings.Contains(prefix, ".") && prefix != "" {
					return true
				}
			}
		}
	}

	return false
}

// extractDNNIDFromCert extracts the DNN ID from certificate's SAN extension
func extractDNNIDFromCert(pemStr string) (string, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return "", fmt.Errorf("failed to decode PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Look for first non-wildcard DNS name in SAN
	for _, dnsName := range cert.DNSNames {
		if !strings.HasPrefix(dnsName, "*.") {
			return strings.ToLower(dnsName), nil
		}
	}

	// Fall back to Common Name if no SAN DNS names
	if cert.Subject.CommonName != "" && !strings.HasPrefix(cert.Subject.CommonName, "*.") {
		return strings.ToLower(cert.Subject.CommonName), nil
	}

	return "", nil
}

// dnnIDMatches checks if the visited DNN name matches the cert's DNN ID
// Matching rules (same as Min browser):
// 1. Exact match: nabobabout === nabobabout
// 2. TLD match: subdomain.nabobabout ends with .nabobabout
// 3. Wildcard: *.nabobabout matches subdomain.nabobabout
func dnnIDMatches(visitedName, certDNNID string) bool {
	visited := strings.ToLower(visitedName)
	certID := strings.ToLower(certDNNID)

	// Exact match
	if visited == certID {
		return true
	}

	// TLD match: visited is subdomain of cert
	// e.g., visited="subdomain.nabobabout", cert="nabobabout"
	if strings.HasSuffix(visited, "."+certID) {
		return true
	}

	// Wildcard match
	// e.g., cert="*.nabobabout", visited="subdomain.nabobabout"
	if strings.HasPrefix(certID, "*.") {
		wildcard := certID[1:] // Remove "*"
		if strings.HasSuffix(visited, wildcard) {
			return true
		}
	}

	return false
}

// ExtractDNNIDFromPEM is exported for use by other packages
func ExtractDNNIDFromPEM(pemStr string) (string, error) {
	return extractDNNIDFromCert(pemStr)
}

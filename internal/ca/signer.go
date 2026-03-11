package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"log"
	"math/big"
	"net"
	"sync"
	"time"
)

const (
	// CertKeyBits is the RSA key size for generated certificates
	CertKeyBits = 2048
	// CertValidDays is how long generated certificates are valid
	CertValidDays = 365 // 1 year, cached for efficiency
)

// CertChecker is an interface for checking if a domain has a valid declared cert
type CertChecker interface {
	// HasDeclaredCert checks if the domain (or its parent) has a declared cert
	HasDeclaredCert(domain string) bool
	// IsCertValidForDomain checks if the declared cert's SAN covers this specific domain
	IsCertValidForDomain(domain string) bool
}

// Signer signs certificates on-the-fly for DNN domains
type Signer struct {
	ca          *CA
	cache       sync.Map // domain -> *tls.Certificate
	untrusted   sync.Map // domain -> *tls.Certificate (for untrusted/self-signed)
	certChecker CertChecker
}

// NewSigner creates a new certificate signer using the given CA
func NewSigner(ca *CA) *Signer {
	return &Signer{
		ca: ca,
	}
}

// SetCertChecker sets the certificate checker (called after cache is created)
func (s *Signer) SetCertChecker(checker CertChecker) {
	s.certChecker = checker
}

// GetCertificate returns a certificate for the given domain
// It caches certificates to avoid regenerating for each connection
func (s *Signer) GetCertificate(domain string) (*tls.Certificate, error) {
	// Check if domain has a valid declared cert with SAN coverage
	// This checks: 1) parent has cert, 2) cert verified, 3) SAN covers this domain
	if s.certChecker != nil && !s.certChecker.IsCertValidForDomain(domain) {
		log.Printf("[CA] ⚠️ No valid cert for %s, generating untrusted certificate", domain)
		return s.getUntrustedCertificate(domain)
	}

	// Check trusted cache first
	if cached, ok := s.cache.Load(domain); ok {
		cert := cached.(*tls.Certificate)
		// Check if still valid (give 1 hour buffer)
		if time.Now().Before(cert.Leaf.NotAfter.Add(-time.Hour)) {
			return cert, nil
		}
		// Expired, regenerate
		s.cache.Delete(domain)
	}

	// Generate new CA-signed certificate
	cert, err := s.generateCert(domain, true)
	if err != nil {
		return nil, err
	}

	// Cache it
	s.cache.Store(domain, cert)
	return cert, nil
}

// getUntrustedCertificate returns a self-signed certificate for untrusted domains
func (s *Signer) getUntrustedCertificate(domain string) (*tls.Certificate, error) {
	// Check untrusted cache first
	if cached, ok := s.untrusted.Load(domain); ok {
		cert := cached.(*tls.Certificate)
		if time.Now().Before(cert.Leaf.NotAfter.Add(-time.Hour)) {
			return cert, nil
		}
		s.untrusted.Delete(domain)
	}

	// Generate self-signed certificate (not signed by trusted CA)
	cert, err := s.generateCert(domain, false)
	if err != nil {
		return nil, err
	}

	s.untrusted.Store(domain, cert)
	return cert, nil
}

// generateCert generates a new certificate for the domain
// If trusted=true, signs with CA. If trusted=false, generates self-signed.
func (s *Signer) generateCert(domain string, trusted bool) (*tls.Certificate, error) {
	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, CertKeyBits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create certificate template
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"DNN"},
			CommonName:   domain,
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(0, 0, CertValidDays),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		// Indicate no revocation checking needed (local proxy cert)
		OCSPServer:            []string{},
		IssuingCertificateURL: []string{},
	}

	// Add SANs (Subject Alternative Names)
	if ip := net.ParseIP(domain); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{domain}
		template.DNSNames = append(template.DNSNames, "*."+domain)
	}

	var certDER []byte
	var certChain [][]byte

	if trusted {
		// Sign with CA - browser will trust this
		certDER, err = x509.CreateCertificate(
			rand.Reader,
			template,
			s.ca.Certificate,
			&privateKey.PublicKey,
			s.ca.PrivateKey,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create certificate: %w", err)
		}
		certChain = [][]byte{certDER, s.ca.Certificate.Raw}
	} else {
		// Self-signed - browser will NOT trust this, showing warning
		template.Subject.Organization = []string{"DNN - UNVERIFIED"}
		certDER, err = x509.CreateCertificate(
			rand.Reader,
			template,
			template, // Self-signed: template is both subject and issuer
			&privateKey.PublicKey,
			privateKey, // Self-signed with own key
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create self-signed certificate: %w", err)
		}
		certChain = [][]byte{certDER}
	}

	// Parse back to get the leaf certificate
	leaf, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return &tls.Certificate{
		Certificate: certChain,
		PrivateKey:  privateKey,
		Leaf:        leaf,
	}, nil
}

// GetTLSConfig returns a TLS config that uses this signer for GetCertificate
func (s *Signer) GetTLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			serverName := hello.ServerName
			// Strip trailing dot from hostname (common in DNS)
			if len(serverName) > 0 && serverName[len(serverName)-1] == '.' {
				serverName = serverName[:len(serverName)-1]
			}
			return s.GetCertificate(serverName)
		},
	}
}

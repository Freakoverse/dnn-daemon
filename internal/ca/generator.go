// Package ca handles local Certificate Authority generation and certificate signing.
//
// This package creates a local CA on each user's machine. The CA is used to sign
// certificates for DNN domains on-the-fly, allowing browsers to trust HTTPS
// connections to DNN sites through the daemon's MITM proxy.
package ca

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"
)

const (
	// CAKeyBits is the RSA key size for the CA
	CAKeyBits = 4096
	// CAValidYears is how long the CA certificate is valid
	// 1000 years = ~10-15 generations (ASN.1 max is year 9999)
	CAValidYears = 1000
)

// CA represents a local Certificate Authority
type CA struct {
	Certificate *x509.Certificate
	PrivateKey  *rsa.PrivateKey
	CertPEM     []byte
	KeyPEM      []byte
}

// CAPath returns the directory where CA files are stored
func CAPath() string {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return filepath.Join(programData, "DNN")
}

// CertPath returns the path to the CA certificate
func CertPath() string {
	return filepath.Join(CAPath(), "dnn-ca.crt")
}

// KeyPath returns the path to the CA private key
func KeyPath() string {
	return filepath.Join(CAPath(), "dnn-ca.key")
}

// Generate creates a new CA key pair and certificate
func Generate() (*CA, error) {
	// Generate RSA private key
	privateKey, err := rsa.GenerateKey(rand.Reader, CAKeyBits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create CA certificate template
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"DNN Local Authority"},
			OrganizationalUnit: []string{"DNN Daemon"},
			CommonName:         "DNN Local CA",
		},
		NotBefore:             now,
		NotAfter:              now.AddDate(CAValidYears, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		MaxPathLen:            1,
	}

	// Self-sign the CA certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create CA certificate: %w", err)
	}

	// Parse the certificate back
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Encode to PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	return &CA{
		Certificate: cert,
		PrivateKey:  privateKey,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
	}, nil
}

// Save saves the CA to disk
func (ca *CA) Save() error {
	// Ensure directory exists
	if err := os.MkdirAll(CAPath(), 0755); err != nil {
		return fmt.Errorf("failed to create CA directory: %w", err)
	}

	// Save certificate (readable by all)
	if err := os.WriteFile(CertPath(), ca.CertPEM, 0644); err != nil {
		return fmt.Errorf("failed to save CA certificate: %w", err)
	}

	// Save private key (restricted access)
	if err := os.WriteFile(KeyPath(), ca.KeyPEM, 0600); err != nil {
		return fmt.Errorf("failed to save CA private key: %w", err)
	}

	return nil
}

// Load loads an existing CA from disk
func Load() (*CA, error) {
	// Read certificate
	certPEM, err := os.ReadFile(CertPath())
	if err != nil {
		return nil, fmt.Errorf("failed to read CA certificate: %w", err)
	}

	// Read private key
	keyPEM, err := os.ReadFile(KeyPath())
	if err != nil {
		return nil, fmt.Errorf("failed to read CA private key: %w", err)
	}

	// Parse certificate
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("failed to decode CA certificate PEM")
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA certificate: %w", err)
	}

	// Parse private key
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode CA private key PEM")
	}

	privateKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CA private key: %w", err)
	}

	return &CA{
		Certificate: cert,
		PrivateKey:  privateKey,
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
	}, nil
}

// LoadOrGenerate loads existing CA or generates a new one
func LoadOrGenerate() (*CA, error) {
	// Try to load existing CA
	if ca, err := Load(); err == nil {
		return ca, nil
	}

	// Generate new CA
	ca, err := Generate()
	if err != nil {
		return nil, err
	}

	// Save it
	if err := ca.Save(); err != nil {
		return nil, err
	}

	return ca, nil
}

// Exists checks if the CA already exists
func Exists() bool {
	_, certErr := os.Stat(CertPath())
	_, keyErr := os.Stat(KeyPath())
	return certErr == nil && keyErr == nil
}

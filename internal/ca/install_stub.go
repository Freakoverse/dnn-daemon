//go:build !windows
// +build !windows

package ca

import "errors"

// InstallToStore installs the CA certificate to the system certificate store
func (ca *CA) InstallToStore() error {
	return errors.New("automatic CA installation not implemented for this platform - manually add the CA cert to your trust store")
}

// RemoveFromStore removes the CA certificate from the system certificate store
func RemoveFromStore() error {
	return errors.New("automatic CA removal not implemented for this platform")
}

// IsInstalledInStore checks if the CA is installed in the system certificate store
func IsInstalledInStore() bool {
	return false
}

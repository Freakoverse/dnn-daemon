//go:build windows
// +build windows

// Package service provides Windows service support for the DNN daemon.
package service

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/debug"
	"golang.org/x/sys/windows/svc/eventlog"
	"golang.org/x/sys/windows/svc/mgr"

	"dnn-daemon/internal/ca"
	"dnn-daemon/internal/capture"
	"dnn-daemon/internal/config"
	"dnn-daemon/internal/httpsproxy"
	"dnn-daemon/internal/mapper"
	"dnn-daemon/internal/peerdiscovery"
	"dnn-daemon/internal/resolver"
)

// runWithTimeout runs a command with a timeout, doesn't block - fire and forget
func runWithTimeout(name string, args ...string) {
	cmd := exec.Command(name, args...)
	cmd.Start() // Start but don't wait - fire and forget
	// Clean up in background after short delay
	go func() {
		time.Sleep(2 * time.Second)
		if cmd.Process != nil {
			cmd.Process.Kill()
		}
	}()
}

const serviceName = "DNNDaemon"
const serviceDesc = "DNN Daemon - Decentralized Naming Network client. Enables any application to access DNN domains."

// DNNService implements the Windows service interface
type DNNService struct {
	cfg        *config.Config
	dnsCapture *capture.Capture
	httpsProxy *httpsproxy.Proxy
	elog       debug.Log
}

// Execute is called by the Windows service manager
func (s *DNNService) Execute(args []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (ssec bool, errno uint32) {
	const cmdsAccepted = svc.AcceptStop | svc.AcceptShutdown

	changes <- svc.Status{State: svc.StartPending}

	// Initialize components
	cache := mapper.NewCache()
	res := resolver.New(s.cfg.Nodes)

	// Start peer discovery (self-healing node pool)
	discovery := peerdiscovery.New(s.cfg.Nodes)
	discovery.Start()

	// Background goroutine to update resolver with discovered nodes
	stopUpdate := make(chan struct{})
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-stopUpdate:
				return
			case <-ticker.C:
				nodes := discovery.GetNodes()
				res.UpdateNodes(nodes)
				s.elog.Info(1, fmt.Sprintf("Updated resolver with %d nodes from peer discovery", len(nodes)))
			}
		}
	}()

	// Create WinDivert DNS capture (no system DNS modification needed!)
	var err error
	s.dnsCapture, err = capture.New(&capture.Config{
		Cache:    cache,
		Resolver: res,
	})
	if err != nil {
		s.elog.Error(1, fmt.Sprintf("Failed to create DNS capture: %v", err))
		changes <- svc.Status{State: svc.StopPending}
		return
	}

	// Start DNS capture
	if err := s.dnsCapture.Start(); err != nil {
		s.elog.Error(1, fmt.Sprintf("Failed to start DNS capture: %v", err))
		changes <- svc.Status{State: svc.StopPending}
		return
	}
	s.elog.Info(1, "WinDivert DNS capture started")

	// Start HTTPS/HTTP proxy if CA exists
	if localCA, err := ca.Load(); err == nil {
		signer := ca.NewSigner(localCA)
		s.httpsProxy = httpsproxy.New("127.0.0.1:443", "127.0.0.1:80", signer, cache, res)
		if err := s.httpsProxy.Start(); err != nil {
			s.elog.Warning(1, fmt.Sprintf("Failed to start proxy: %v", err))
		} else {
			s.elog.Info(1, "HTTP/HTTPS proxy started on 127.0.0.1:80 and :443")
		}
	} else {
		s.elog.Warning(1, fmt.Sprintf("CA not found, proxy disabled: %v", err))
	}

	changes <- svc.Status{State: svc.Running, Accepts: cmdsAccepted}
	s.elog.Info(1, "DNN Daemon started with WinDivert DNS interception")

loop:
	for c := range r {
		switch c.Cmd {
		case svc.Interrogate:
			changes <- c.CurrentStatus
		case svc.Stop, svc.Shutdown:
			s.elog.Info(1, "Service stopping...")
			break loop
		default:
			s.elog.Error(1, fmt.Sprintf("Unexpected control request: %d", c))
		}
	}

	changes <- svc.Status{State: svc.StopPending}

	// Stop components
	close(stopUpdate)
	discovery.Stop()
	if s.dnsCapture != nil {
		s.dnsCapture.Stop()
	}
	if s.httpsProxy != nil {
		s.httpsProxy.Stop()
	}
	return
}

// RunService runs the daemon as a Windows service
func RunService(cfg *config.Config, isDebug bool) error {
	var elog debug.Log
	var err error

	if isDebug {
		elog = debug.New(serviceName)
	} else {
		elog, err = eventlog.Open(serviceName)
		if err != nil {
			return fmt.Errorf("failed to open event log: %w", err)
		}
	}
	defer elog.Close()

	elog.Info(1, fmt.Sprintf("Starting %s service", serviceName))

	run := svc.Run
	if isDebug {
		run = debug.Run
	}

	s := &DNNService{cfg: cfg, elog: elog}
	err = run(serviceName, s)
	if err != nil {
		elog.Error(1, fmt.Sprintf("Service failed: %v", err))
		return err
	}

	elog.Info(1, fmt.Sprintf("%s service stopped", serviceName))
	return nil
}

// IsWindowsService checks if we're running as a Windows service
func IsWindowsService() bool {
	isInteractive, err := svc.IsWindowsService()
	if err != nil {
		return false
	}
	return isInteractive
}

// InstallService installs the Windows service and copies config
func InstallService(exePath, sourceConfigPath string) error {
	// Ensure config directory exists
	configDir := filepath.Dir(DefaultConfigPath())
	if err := os.MkdirAll(configDir, 0755); err != nil {
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	// Copy config file to ProgramData if it doesn't exist
	destConfigPath := DefaultConfigPath()
	if _, err := os.Stat(destConfigPath); os.IsNotExist(err) {
		if sourceConfigPath != "" && sourceConfigPath != destConfigPath {
			if err := copyFile(sourceConfigPath, destConfigPath); err != nil {
				// If source doesn't exist either, create default config
				if os.IsNotExist(err) {
					if err := createDefaultConfig(destConfigPath); err != nil {
						return fmt.Errorf("failed to create default config: %w", err)
					}
					fmt.Printf("Created default config at: %s\n", destConfigPath)
				} else {
					return fmt.Errorf("failed to copy config: %w", err)
				}
			} else {
				fmt.Printf("Config copied to: %s\n", destConfigPath)
			}
		} else {
			// Create default config
			if err := createDefaultConfig(destConfigPath); err != nil {
				return fmt.Errorf("failed to create default config: %w", err)
			}
			fmt.Printf("Created default config at: %s\n", destConfigPath)
		}
	}

	// Connect to service manager
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	// Check if service already exists
	s, err := m.OpenService(serviceName)
	if err == nil {
		// Service exists - check if it's stopped/stale and clean it up
		status, queryErr := s.Query()
		if queryErr == nil && status.State == svc.Stopped {
			fmt.Println("Found stopped service, cleaning up...")

			// Force kill any remaining processes (with timeout to prevent hanging)
			fmt.Println("  Killing any remaining processes...")
			runWithTimeout("taskkill", "/F", "/IM", "dnn-daemon.exe")
			runWithTimeout("wmic", "process", "where", "name='dnn-daemon.exe'", "delete")
			time.Sleep(500 * time.Millisecond)

			// Delete the old service
			fmt.Println("  Deleting old service entry...")
			if delErr := s.Delete(); delErr != nil {
				s.Close()
				return fmt.Errorf("failed to delete existing service: %w (try restarting your computer)", delErr)
			}
			s.Close()
			fmt.Println("  Service marked for deletion.")

			// Wait for deletion to complete (timeout after 5 seconds)
			fmt.Print("  Waiting for removal")
			serviceGone := false
			for i := 0; i < 10; i++ {
				fmt.Print(".")
				time.Sleep(500 * time.Millisecond)
				testS, testErr := m.OpenService(serviceName)
				if testErr != nil {
					// Service is gone
					serviceGone = true
					break
				}
				testS.Close()
			}
			fmt.Println()

			if !serviceGone {
				fmt.Println("  Warning: Service still exists (marked for deletion).")
				fmt.Println("  Will attempt to create new service anyway...")
			} else {
				fmt.Println("  Old service removed successfully.")
			}
		} else {
			s.Close()
			return fmt.Errorf("service %s already exists and is running - uninstall first", serviceName)
		}
	}

	// Create the service
	fmt.Println("Creating new service...")
	s, err = m.CreateService(serviceName, exePath, mgr.Config{
		DisplayName: "DNN Daemon",
		Description: serviceDesc,
		StartType:   mgr.StartAutomatic,
	}, "--service", "--config", destConfigPath)
	if err != nil {
		return fmt.Errorf("failed to create service: %w", err)
	}
	fmt.Println("Service created successfully.")

	// Set up event log (try to remove old one first, then create new)
	eventlog.Remove(serviceName) // Ignore errors - might not exist
	err = eventlog.InstallAsEventCreate(serviceName, eventlog.Error|eventlog.Warning|eventlog.Info)
	if err != nil {
		// Just warn, don't fail - event log is nice to have but not critical
		fmt.Printf("Warning: Event log setup failed (may already exist): %v\n", err)
	}

	// Generate and install CA for HTTPS support
	fmt.Println("Setting up Certificate Authority for HTTPS support...")

	// Clean up any old DNN certificates first
	fmt.Println("Cleaning up old certificates...")
	ca.CleanupOldCerts()

	// Delete existing CA files to force regeneration with new settings
	if ca.Exists() {
		os.Remove(ca.CertPath())
		os.Remove(ca.KeyPath())
	}

	// Generate fresh CA
	localCA, err := ca.Generate()
	if err != nil {
		fmt.Printf("Warning: Failed to generate CA: %v\n", err)
	} else {
		if err := localCA.Save(); err != nil {
			fmt.Printf("Warning: Failed to save CA: %v\n", err)
		}
		fmt.Printf("CA generated at: %s\n", ca.CertPath())
		fmt.Println("Installing CA to Windows certificate store...")
		if err := localCA.InstallToStore(); err != nil {
			fmt.Printf("Warning: Failed to install CA: %v\n", err)
			fmt.Println("You may need to manually install the CA certificate.")
		} else {
			fmt.Println("CA installed to Windows trust store. HTTPS will now work!")
		}
	}

	// No DNS configuration needed - WinDivert intercepts DNS packets directly!
	fmt.Println("WinDivert mode: No DNS modification required.")

	// Add IPv6 route for fd00::/8 to localhost (for transport interception)
	fmt.Println("Adding IPv6 route for transport interception...")
	addRoute := exec.Command("netsh", "interface", "ipv6", "add", "route", "fd00::/8", "interface=1")
	if err := addRoute.Run(); err != nil {
		// Route might already exist, try to delete and re-add
		delRoute := exec.Command("netsh", "interface", "ipv6", "delete", "route", "fd00::/8", "interface=1")
		delRoute.Run()
		if err := addRoute.Run(); err != nil {
			fmt.Printf("Warning: Failed to add IPv6 route: %v\n", err)
			fmt.Println("Transport interception may not work.")
		} else {
			fmt.Println("IPv6 route added for fd00::/8")
		}
	} else {
		fmt.Println("IPv6 route added for fd00::/8")
	}

	// Start the service
	fmt.Println("Starting DNN Daemon service...")
	if err := s.Start(); err != nil {
		fmt.Printf("Warning: Failed to start service: %v\n", err)
		fmt.Println("You can start it manually with: sc start DNNDaemon")
	} else {
		fmt.Println("DNN Daemon service started successfully!")
	}

	s.Close()
	return nil
}

// UninstallService removes the Windows service
func UninstallService() error {
	// No DNS restoration needed - WinDivert doesn't modify system DNS

	// Remove IPv6 route for fd00::/8
	fmt.Println("Removing IPv6 route...")
	delRoute := exec.Command("netsh", "interface", "ipv6", "delete", "route", "fd00::/8", "interface=1")
	if err := delRoute.Run(); err != nil {
		fmt.Printf("Warning: Failed to remove IPv6 route: %v\n", err)
	} else {
		fmt.Println("IPv6 route removed.")
	}

	// Remove CA from Windows cert store
	fmt.Println("Removing CA from Windows certificate store...")
	if err := ca.RemoveFromStore(); err != nil {
		fmt.Printf("Warning: Failed to remove CA from store: %v\n", err)
	} else {
		fmt.Println("CA removed from Windows certificate store.")
	}

	// Delete CA files
	if ca.Exists() {
		os.Remove(ca.CertPath())
		os.Remove(ca.KeyPath())
		fmt.Println("CA files deleted.")
	}

	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", serviceName)
	}
	defer s.Close()

	// Get service status and PID before stopping
	status, err := s.Query()
	var servicePID uint32
	if err == nil {
		servicePID = status.ProcessId
	}

	// Stop the service if running
	if err == nil && status.State != svc.Stopped {
		fmt.Println("Stopping service...")
		s.Control(svc.Stop)

		// Wait for service to stop (up to 10 seconds)
		for i := 0; i < 20; i++ {
			time.Sleep(500 * time.Millisecond)
			status, err = s.Query()
			if err != nil || status.State == svc.Stopped {
				break
			}
		}
	}

	// If service process is still running, kill it by PID (not by name!)
	// This is safe because we're killing the SERVICE's PID, not our own uninstaller PID
	if servicePID > 0 {
		// Check if it's not our own process
		if servicePID != uint32(os.Getpid()) {
			fmt.Printf("Killing service process (PID %d)...\n", servicePID)
			killCmd := exec.Command("taskkill", "/F", "/PID", fmt.Sprintf("%d", servicePID))
			killCmd.Run() // Ignore errors - process might already be gone

			// Wait for process to fully terminate
			time.Sleep(3 * time.Second)
		}
	}

	fmt.Println("Deleting service...")
	err = s.Delete()
	if err != nil {
		return fmt.Errorf("failed to delete service: %w", err)
	}
	fmt.Println("Service deleted.")

	// Wait and poll for service to be fully removed (not just marked for deletion)
	fmt.Print("Waiting for service removal")
	for i := 0; i < 10; i++ {
		fmt.Print(".")
		time.Sleep(500 * time.Millisecond)
		// Try to open - if it fails, service is truly gone
		testS, testErr := m.OpenService(serviceName)
		if testErr != nil {
			fmt.Println(" done!")
			break
		}
		testS.Close()
		if i == 9 {
			fmt.Println(" (may complete after restart)")
		}
	}

	fmt.Println("Removing event log...")
	err = eventlog.Remove(serviceName)
	if err != nil {
		fmt.Printf("Warning: failed to remove event log: %v\n", err)
	}

	fmt.Println("")
	fmt.Println("=== DNN Daemon uninstalled successfully! ===")
	return nil
}

// DefaultConfigPath returns the default config path on Windows
func DefaultConfigPath() string {
	programData := os.Getenv("ProgramData")
	if programData == "" {
		programData = `C:\ProgramData`
	}
	return filepath.Join(programData, "DNN", "dnn-daemon.yaml")
}

// copyFile copies a file from src to dst
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destFile.Close()

	_, err = io.Copy(destFile, sourceFile)
	return err
}

// createDefaultConfig creates a default config file
func createDefaultConfig(path string) error {
	defaultConfig := `# DNN Daemon Configuration

# DNN nodes to use for name resolution (failover in order)
nodes:
  - https://node.icannot.xyz
  - http://64.111.92.122:8080

# Resolution cache settings
cache:
  ttl: 60s
  max_entries: 10000

# TUN device settings (Linux)
tun:
  name: dnn0
  mtu: 1420

# Local DNS server settings
dns:
  listen_addr: "127.0.0.1:53"
  domain: "dnn"

# Logging
log:
  level: info
`
	return os.WriteFile(path, []byte(defaultConfig), 0644)
}

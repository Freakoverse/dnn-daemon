// DNN Daemon - System service that makes any application DNN-aware
//
// WinDivert-based DNS interception:
// - Captures DNS packets BEFORE routing using WinDivert driver
// - No system DNS modification needed - intercepts all UDP port 53
// - Works alongside other VPNs, no routing conflicts
//
// Components:
//   - Capture: WinDivert-based DNS packet interception
//   - Mapper: Converts DNN names to/from IPv6 addresses
//   - Resolver: Queries DNN nodes for name resolution
//   - Proxy: Handles TCP/TLS connections with certificate verification
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"dnn-daemon/internal/ca"
	"dnn-daemon/internal/capture"
	"dnn-daemon/internal/config"
	"dnn-daemon/internal/httpsproxy"
	"dnn-daemon/internal/mapper"
	"dnn-daemon/internal/peerdiscovery"
	"dnn-daemon/internal/resolver"
	"dnn-daemon/internal/service"
)

var (
	configPath     = flag.String("config", "", "Path to configuration file")
	version        = flag.Bool("version", false, "Print version and exit")
	installService = flag.Bool("install", false, "Install as Windows service")
	removeService  = flag.Bool("uninstall", false, "Uninstall Windows service")
	runAsService   = flag.Bool("service", false, "Run as Windows service (internal)")
	debugMode      = flag.Bool("debug", false, "Run in debug mode")
)

const Version = "0.1.0"

func main() {
	flag.Parse()

	if *version {
		fmt.Printf("dnn-daemon version %s (%s/%s)\n", Version, runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	// Determine config path
	cfgPath := *configPath
	if cfgPath == "" {
		cfgPath = service.DefaultConfigPath()
	}

	// Handle interactive install mode (double-click / no args)
	// Works on Windows, Linux, and macOS
	if !*installService && !*removeService && !*runAsService && !*debugMode && *configPath == "" {
		if runtime.GOOS == "windows" && !service.IsWindowsService() {
			handleInteractiveInstall()
			return
		} else if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
			handleInteractiveInstall()
			return
		}
	}

	// Handle --install flag (command line install)
	if *installService {
		if !service.IsAdmin() {
			if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
				log.Fatal("Please run with sudo: sudo ./dnn-daemon --install")
			} else {
				service.RequestElevation()
				return
			}
		}
		exePath, err := os.Executable()
		if err != nil {
			log.Fatalf("Failed to get executable path: %v", err)
		}
		if err := service.InstallService(exePath, cfgPath); err != nil {
			log.Fatalf("Failed to install service: %v", err)
		}
		fmt.Println("DNN Daemon service installed successfully.")
		switch runtime.GOOS {
		case "windows":
			fmt.Println("Start it with: sc start DNNDaemon")
		case "darwin":
			fmt.Println("Start it with: sudo launchctl load /Library/LaunchDaemons/xyz.dnn.daemon.plist")
		default:
			fmt.Println("Start it with: sudo systemctl start dnn-daemon")
		}
		return
	}

	// Handle --uninstall flag
	if *removeService {
		if !service.IsAdmin() {
			if runtime.GOOS == "linux" || runtime.GOOS == "darwin" {
				log.Fatal("Please run with sudo: sudo ./dnn-daemon --uninstall")
			} else {
				service.RequestElevation()
				return
			}
		}
		if err := service.UninstallService(); err != nil {
			log.Fatalf("Failed to uninstall service: %v", err)
		}
		fmt.Println("DNN Daemon service uninstalled successfully.")
		fmt.Println("")
		fmt.Println("NOTE: If you connected to different WiFi networks while the daemon")
		fmt.Println("was running, those networks may still have DNS set to 127.0.0.1.")
		fmt.Println("If your internet doesn't work on another network, reset DNS to DHCP:")
		fmt.Println("  Settings -> Network & Internet -> Wi-Fi -> [Network] -> DNS = Automatic")
		return
	}

	// Handle Windows service mode
	if runtime.GOOS == "windows" {
		if *runAsService || service.IsWindowsService() {
			cfg, err := config.Load(cfgPath)
			if err != nil {
				cfg = config.DefaultConfig()
			}
			if err := service.RunService(cfg, *debugMode); err != nil {
				log.Fatalf("Service error: %v", err)
			}
			return
		}
	}

	// Run in foreground mode
	runForeground(cfgPath)
}

// handleInteractiveInstall handles the case when exe is double-clicked (no args)
// Shows GUI dialogs for user-friendly install experience
func handleInteractiveInstall() {
	cfgPath := service.DefaultConfigPath()

	// Request admin rights FIRST, before showing any dialogs
	if !service.IsAdmin() {
		service.RequestElevation()
		return
	}

	// Show main action dialog: Install / Uninstall / Cancel
	isInstalled := service.IsServiceInstalled()
	action := service.ShowMainActionDialog(isInstalled)

	switch action {
	case service.ActionInstall:
		// Show node configuration dialog
		defaultNodes := config.DefaultConfig().Nodes
		nodeList := service.ShowNodeConfigDialog(defaultNodes)
		if nodeList == nil {
			// User cancelled
			return
		}

		// Save custom node config if provided
		if len(nodeList) > 0 {
			cfg := config.DefaultConfig()
			cfg.Nodes = nodeList
			// Ensure config directory exists
			if err := os.MkdirAll(filepath.Dir(cfgPath), 0755); err == nil {
				cfg.Save(cfgPath)
			}
		}

		// Perform the actual install
		exePath, err := os.Executable()
		if err != nil {
			service.ShowInstallError(err)
			return
		}

		if err := service.InstallService(exePath, cfgPath); err != nil {
			service.ShowInstallError(err)
			return
		}

		service.ShowInstallSuccess()

	case service.ActionUninstall:
		if err := service.UninstallService(); err != nil {
			service.ShowInstallError(err)
			return
		}
		service.ShowUninstallSuccess()

	case service.ActionCancel:
		// User cancelled, do nothing
		return
	}
}

func runForeground(cfgPath string) {
	// Load configuration
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Printf("[Daemon] Config file not found at %s, using defaults", cfgPath)
		cfg = config.DefaultConfig()
	}

	log.Printf("[Daemon] DNN Daemon v%s starting...", Version)
	log.Printf("[Daemon] Using %d DNN nodes", len(cfg.Nodes))
	log.Printf("[Daemon] Mode: WinDivert-based DNS interception (no system DNS modification)")

	// Initialize components
	cache := mapper.NewCache()
	res := resolver.New(cfg.Nodes)

	// Start peer discovery (self-healing node pool)
	discovery := peerdiscovery.New(cfg.Nodes)
	discovery.Start()

	// Initialize CA signer for HTTPS proxy
	caInst, err := ca.LoadOrGenerate()
	if err != nil {
		log.Fatalf("[Daemon] Failed to initialize CA: %v", err)
	}
	signer := ca.NewSigner(caInst)
	prx := httpsproxy.New("127.0.0.1:443", "127.0.0.1:80", signer, cache, res)

	// Create WinDivert DNS capture
	dnsCapture, err := capture.New(&capture.Config{
		Cache:    cache,
		Resolver: res,
	})
	if err != nil {
		log.Fatalf("[Daemon] Failed to create DNS capture (run as admin): %v", err)
	}
	log.Printf("[Daemon] Created WinDivert DNS capture")

	// Create context for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle signals
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Start DNS capture (intercepts all UDP/53 packets)
	go func() {
		log.Printf("[Daemon] Starting DNS capture (intercepting all UDP port 53)")
		if err := dnsCapture.Start(); err != nil {
			log.Printf("[Daemon] DNS capture error: %v", err)
		}
	}()

	// Start HTTPS proxy server
	go func() {
		log.Printf("[Daemon] Starting HTTPS proxy on 127.0.0.1:443")
		if err := prx.Start(); err != nil {
			log.Printf("[Daemon] HTTPS proxy error: %v", err)
		}
	}()

	// Periodically update resolver with discovered nodes
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				nodes := discovery.GetNodes()
				res.UpdateNodes(nodes)
				log.Printf("[Daemon] Updated resolver with %d nodes from peer discovery", len(nodes))
			}
		}
	}()

	// Print usage instructions
	printUsageInstructions(cfg)

	// Wait for shutdown signal
	select {
	case sig := <-sigCh:
		log.Printf("[Daemon] Received signal %v, shutting down...", sig)
		cancel()
	case <-ctx.Done():
	}

	// Cleanup
	discovery.Stop()
	prx.Stop()
	dnsCapture.Stop()
	capture.CleanupWinDivert()

	log.Printf("[Daemon] Shutdown complete")
}

func printUsageInstructions(cfg *config.Config) {
	log.Println("")
	log.Println("=== DNN Daemon Running ===")
	log.Println("")
	log.Println("WinDivert capturing all DNS (UDP port 53)")
	log.Println("DNN names are detected by pattern (n + 4+ chars + BIP39 word)")
	log.Println("")
	log.Println("Access DNN sites like:")
	log.Println("  https://nabobabout/")
	log.Println("  https://domainName1.nabobabout/")
	log.Println("  https://domainName2.nabobabout/")
	log.Println("")
	log.Println("Press Ctrl+C to stop")
	log.Println("==========================")
	log.Println("")
}

func getDefaultConfigPath() string {
	if runtime.GOOS == "windows" {
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		return filepath.Join(programData, "DNN", "dnn-daemon.yaml")
	}
	return "/etc/dnn/dnn-daemon.yaml"
}

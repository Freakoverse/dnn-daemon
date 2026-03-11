# DNN Daemon Installation Guide

> **Cross-Platform**: Works on Windows, Linux, and macOS  
> **One-Click**: Just double-click to install

The DNN Daemon makes any application (browser, curl, etc.) DNN-aware by intercepting DNS queries and proxying HTTPS connections with automatic certificate verification.

---

## Download

Get the latest binary from [GitHub Releases](https://github.com/Freakoverse/dnn-daemon/releases).

| Platform | Binary |
|----------|--------|
| Windows x64 | `dnn-daemon-windows-amd64.exe` |
| Windows ARM | `dnn-daemon-windows-arm64.exe` |
| Linux x64 | `dnn-daemon-linux-amd64` |
| Linux ARM | `dnn-daemon-linux-arm64` |
| macOS Apple Silicon | `dnn-daemon-darwin-arm64` |
| macOS Intel | `dnn-daemon-darwin-amd64` |

---

## Quick Start

### Windows

1. Download `dnn-daemon-windows-amd64.exe`
2. Double-click the exe
3. Accept the UAC prompt
4. Click **Yes** to install → Configure nodes → Done!

### Linux (Ubuntu, ZorinOS, Debian, etc.)

1. Download `dnn-daemon-linux-amd64`
2. Make it executable and install:
   ```bash
   chmod +x dnn-daemon-linux-amd64
   sudo ./dnn-daemon-linux-amd64 --install
   ```
3. Verify it's running:
   ```bash
   systemctl status dnn-daemon
   ```

### macOS

1. Download `dnn-daemon-darwin-arm64` (Apple Silicon) or `dnn-daemon-darwin-amd64` (Intel)
2. Right-click → Open (bypass Gatekeeper)
3. Enter password when prompted
4. Choose **Install** → Configure nodes → Done!

---

## What Gets Installed

| Component | Windows | Linux | macOS |
|-----------|---------|-------|-------|
| **Service** | Windows Service (DNNDaemon) | systemd unit | launchd plist |
| **Binary** | `%ProgramFiles%\DNN\dnn-daemon.exe` | `/usr/local/bin/dnn-daemon` | `/usr/local/bin/dnn-daemon` |
| **Config** | `%ProgramData%\DNN\config.yaml` | `/etc/dnn/dnn-daemon.yaml` | `/usr/local/etc/dnn/dnn-daemon.yaml` |
| **CA Cert** | Windows Certificate Store | System CA store | macOS Keychain |
| **DNS Interception** | WinDivert driver | iptables NAT redirect | TUN interface |

---

## How DNS Interception Works

Each platform uses a different method to capture DNS queries:

### Windows — WinDivert
- Captures DNS packets at the kernel level using the WinDivert driver
- No system DNS settings are modified
- `WinDivert.dll` and `WinDivert64.sys` are bundled with the binary

### Linux — iptables NAT Redirect
- Adds two iptables rules in the OUTPUT chain:
  1. `RETURN` rule for the daemon's own UID (prevents DNS loop)
  2. `REDIRECT` rule: UDP port 53 → port 15353 (daemon's local DNS server)
- The daemon's own upstream queries to 8.8.8.8 bypass the redirect
- Rules are automatically removed on shutdown/uninstall

### macOS — TUN Interface
- Creates a TUN interface for DNS interception
- Routes DNS traffic through the daemon

---

## Command Line Usage

```bash
# Install as system service
sudo ./dnn-daemon --install

# Uninstall (stops service, removes iptables rules, removes CA cert)
sudo ./dnn-daemon --uninstall

# Run in foreground for debugging
sudo ./dnn-daemon --debug

# Run with custom config
sudo ./dnn-daemon --config /path/to/config.yaml
```

---

## Uninstalling

**Option 1: Command Line (recommended)**
```bash
# Windows (Admin PowerShell)
.\dnn-daemon.exe --uninstall

# Linux/macOS
sudo ./dnn-daemon --uninstall
```

**Option 2: GUI**
- Double-click the binary again → Choose **Uninstall**

> [!WARNING]
> **Windows Users**: If you connected to multiple WiFi networks while the daemon was running, those networks may still have DNS set to 127.0.0.1. If internet breaks on another network, go to Settings → Network & Internet → Wi-Fi → [Your Network] → Hardware properties → Set DNS to "Automatic (DHCP)".

### Emergency: Internet Broken (Linux)

If the daemon crashes without cleaning up iptables, your DNS will stop working. Fix it manually:

```bash
# Remove iptables rules immediately
sudo iptables -t nat -D OUTPUT -p udp --dport 53 -j REDIRECT --to-port 15353
sudo iptables -t nat -D OUTPUT -p udp --dport 53 -m owner --uid-owner 0 -j RETURN

# Stop the daemon
sudo systemctl stop dnn-daemon
```

Your internet should come back instantly.

---

## Node Configuration

During installation, you can configure which DNN nodes to use.

**Default seed nodes:**
- `https://node.icannot.xyz`
- `http://64.111.92.122:8080`

The daemon automatically discovers additional nodes by crawling peers from connected nodes.

---

## Troubleshooting

### "Can't access DNN sites"

1. Check if daemon is running:
   ```bash
   # Windows
   sc query DNNDaemon

   # Linux
   systemctl status dnn-daemon

   # macOS
   launchctl list | grep dnn
   ```

2. Test DNS resolution:
   ```bash
   # Windows
   nslookup nabandonaread 127.0.0.1

   # Linux/macOS
   dig @127.0.0.1 nabandonaread
   ```

3. Run in debug mode:
   ```bash
   # Stop service first
   sudo systemctl stop dnn-daemon  # or: sc stop DNNDaemon

   # Run with visible logs
   sudo ./dnn-daemon --debug
   ```

### "Certificate errors in browser"

The DNN CA certificate may not be trusted by your browser. Re-run the installer to reinstall the CA certificate.

### Service Logs

| Platform | Command |
|----------|---------|
| Windows | Event Viewer → Windows Logs → Application → Filter by "DNNDaemon" |
| Linux | `journalctl -u dnn-daemon -f` |
| macOS | `cat /var/log/dnn-daemon.log` |

---

## Building from Source

Requires Go 1.21+.

```bash
cd daemon

# Windows
go build -o dnn-daemon.exe ./cmd/dnn-daemon

# Linux
GOOS=linux GOARCH=amd64 go build -o dnn-daemon-linux-amd64 ./cmd/dnn-daemon

# macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o dnn-daemon-darwin-arm64 ./cmd/dnn-daemon

# macOS (Intel)
GOOS=darwin GOARCH=amd64 go build -o dnn-daemon-darwin-amd64 ./cmd/dnn-daemon
```

---

## Architecture

| Component | File | Purpose |
|-----------|------|---------|
| Entry point | `cmd/dnn-daemon/main.go` | CLI handling, install/uninstall |
| DNS Capture (Win) | `internal/capture/capture_windows.go` | WinDivert DNS interception |
| DNS Capture (Linux) | `internal/capture/capture_linux.go` | iptables NAT redirect |
| DNS Capture (macOS) | `internal/capture/capture_darwin.go` | TUN-based interception |
| Detector | `internal/detector/detector.go` | BIP39 two-word pattern matching |
| Resolver | `internal/resolver/resolver.go` | Multi-node parallel resolution |
| Cert Verifier | `internal/certverify/certverify.go` | 62600 cert PEM matching |
| HTTPS Proxy | `internal/httpsproxy/proxy.go` | TLS termination & proxying |
| Config | `internal/config/config.go` | YAML configuration loading |
| Service | `internal/service/` | Platform service management |
| Peer Discovery | `internal/peerdiscovery/` | Automatic node pool management |

---

*Last updated: 2026-03-11*

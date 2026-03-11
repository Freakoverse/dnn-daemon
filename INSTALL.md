# DNN Daemon Installation Guide

> **Cross-Platform**: Works on Windows, Linux, and macOS  
> **One-Click**: Just double-click to install

The DNN Daemon makes any application (browser, curl, etc.) DNN-aware by running a local DNS server and HTTPS proxy.

---

## Quick Start

### Windows

1. Download `dnn-daemon.exe`
2. Double-click the exe
3. Accept the UAC prompt
4. Click **Yes** to install → Configure nodes → Done!

### Linux

1. Download `dnn-daemon-linux-amd64`
2. Right-click → Properties → "Allow executing as program"
3. Double-click (or run `sudo ./dnn-daemon-linux-amd64`)
4. Enter password when prompted
5. Choose **Install** → Configure nodes → Done!

### macOS

1. Download `dnn-daemon-darwin-arm64` (Apple Silicon) or `dnn-daemon-darwin-amd64` (Intel)
2. Right-click → Open (bypass Gatekeeper)
3. Enter password when prompted
4. Choose **Install** → Configure nodes → Done!

---

## What Gets Installed

| Component | Windows | Linux | macOS |
|-----------|---------|-------|-------|
| **Service** | Windows Service (DNNDaemon) | systemd | launchd |
| **Binary** | `%ProgramFiles%\DNN\dnn-daemon.exe` | `/usr/local/bin/dnn-daemon` | `/usr/local/bin/dnn-daemon` |
| **Config** | `%ProgramData%\DNN\config.yaml` | `/etc/dnn/dnn-daemon.yaml` | `/usr/local/etc/dnn/dnn-daemon.yaml` |
| **CA Cert** | Windows Certificate Store | System CA store | macOS Keychain |
| **DNS** | Network adapter settings | `/etc/resolv.conf` or systemd-resolved | networksetup |

---

## Command Line Usage

```bash
# Install (with GUI dialogs)
./dnn-daemon --install

# Uninstall
./dnn-daemon --uninstall

# Run in foreground (debugging)
./dnn-daemon --debug

# Run with custom config
./dnn-daemon --config /path/to/config.yaml
```

---

## Uninstalling

**Option 1: GUI**
- Double-click the exe/binary again
- Choose **Uninstall**

**Option 2: Command Line**
```bash
# Windows (as Administrator)
.\dnn-daemon.exe --uninstall

# Linux/macOS
sudo ./dnn-daemon --uninstall
```

> [!WARNING]
> **Windows Users**: If you connected to multiple WiFi networks while the daemon was running, those networks may still have DNS set to 127.0.0.1. If internet breaks on another network, go to Settings → Network & Internet → Wi-Fi → [Your Network] → Hardware properties → Set DNS to "Automatic (DHCP)".

---

## How It Works

DNN domains are detected by **pattern**, not by a fixed TLD. This allows them to coexist with normal DNS:

```
Pattern: n + 4+ characters + BIP39 word
Examples: nabobabout, nabceabsurd, freakoverse.nabobabout
```

```
┌─────────────────────┐
│  Any Application    │
│  (browser, curl)    │
└─────────────────────┘
          │
          ▼ DNS query: nabobabout?
┌─────────────────────┐
│  DNN Daemon         │
│  ├─ DNS Server      │ → Pattern detection → 127.0.0.1
│  ├─ Resolver        │ → DNN Node API
│  └─ HTTPS Proxy     │ → 127.0.0.1:443
└─────────────────────┘
          │
          ▼
┌─────────────────────┐
│  Destination Server │
│  (with cert verify) │
└─────────────────────┘
```

1. **DNS Query**: App queries `nabobabout`
2. **Pattern Detection**: Daemon detects DNN pattern → returns 127.0.0.1
3. **Resolution**: Daemon queries DNN nodes for the real IP:port
4. **Certificate Verification**: Daemon verifies server's TLS cert against declared cert in DNN
5. **Proxy**: Daemon proxies the connection to the destination

---

## Node Configuration

During installation, you can configure which DNN nodes to use:

**Default nodes:**
- `https://node.icannot.xyz`
- `http://64.111.92.122:8080`

The daemon will also **automatically discover** additional nodes by querying connected nodes for their peer lists.

---

## Troubleshooting

### "Can't access DNN sites"

1. Check if daemon is running:
   - Windows: `sc query DNNDaemon`
   - Linux: `systemctl status dnn-daemon`
   - macOS: `launchctl list | grep dnn`

2. Check DNS is configured:
   - Windows: `nslookup nabobabout 127.0.0.1`
   - Linux/macOS: `dig @127.0.0.1 nabobabout`

3. Try debug mode:
   ```bash
   # Stop service first
   sc stop DNNDaemon  # or systemctl stop dnn-daemon
   
   # Run in debug mode to see logs
   ./dnn-daemon --debug
   ```

### "Certificate errors in browser"

The DNN CA certificate may not be trusted. Re-run the installer to reinstall the CA.

### "Internet broken after uninstall" (Windows)

If you connected to multiple WiFi networks while the daemon was running, those networks may still have DNS set to 127.0.0.1. Go to Settings → Network & Internet → Wi-Fi → [Your Network] → DNS → Set to "Automatic (DHCP)".

### Service logs

- Windows: Event Viewer → Windows Logs → Application → Filter by "DNNDaemon"
- Linux: `journalctl -u dnn-daemon -f`
- macOS: `cat /var/log/dnn-daemon.log`

---

## Building from Source

```bash
cd DNN/daemon

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
| Main | `cmd/dnn-daemon/main.go` | Entry point, CLI handling |
| DNS Server | `internal/dns/server.go` | Pattern-based DNN detection |
| Detector | `internal/detector/detector.go` | BIP39 pattern matching |
| Resolver | `internal/resolver/resolver.go` | DNN node API client |
| HTTPS Proxy | `internal/httpsproxy/proxy.go` | TLS proxy with cert verification |
| Config | `internal/config/config.go` | YAML configuration |
| Service (Win) | `internal/service/service_windows.go` | Windows Service |
| Service (Linux) | `internal/service/service_linux.go` | systemd |
| Service (macOS) | `internal/service/service_darwin.go` | launchd |
| Dialogs | `internal/service/dialogs_*.go` | Platform-specific GUI dialogs |

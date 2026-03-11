# DNN Daemon

System daemon that makes any application DNN-aware by detecting DNN domain patterns and proxying HTTPS connections with automatic certificate verification.

## Quick Install

Download from [GitHub Releases](https://github.com/Freakoverse/dnn-daemon/releases).

| Platform | Binary | Install |
|----------|--------|---------|
| Windows | `dnn-daemon-windows-amd64.exe` | Double-click → Yes → Done |
| Linux | `dnn-daemon-linux-amd64` | `chmod +x` → run with `sudo` |
| macOS ARM | `dnn-daemon-darwin-arm64` | Right-click → Open → Enter password |
| macOS Intel | `dnn-daemon-darwin-amd64` | Right-click → Open → Enter password |

## How It Works

DNN domains are detected by **pattern**, not by TLD like `.dnn`:

```
Format: n{word1}{word2}[{cycle}]{posLetters}
  word1, word2 = BIP39 words (encode block number)
  cycle        = optional digits (omitted for cycle 0)
  posLetters   = bijective base-26 position (a=1, z=26, aa=27)

Examples: nabandonaread, nabtaabovea, nabandonzooa
```

This means DNN domains work alongside regular DNS without collision.

## Features

### 🔒 Certificate Verification
The daemon verifies server certificates against declarations in DNN's 62600 connection events:
- **Valid cert**: Browser shows normal HTTPS padlock
- **Missing/mismatched cert**: Browser shows "Your connection is not private" warning with option to proceed

### 🌐 Subdomain Support
Subdomains are validated against the DNN name event's `o` tags:
- `banana.nabtaabove` resolves only if `banana` is declared in the name event
- Each subdomain can have its own certificate in the 62600 connection event
- Invalid subdomains return 404

### 🔁 Multi-Node Resolution
Queries **3 random nodes in parallel** for every resolution:
- Verifies Schnorr signatures on connection events (via `go-nostr`)
- Checks pubkey consistency across responses
- Picks the freshest `created_at` as the latest truth
- Respects `domain_found` flag — removed domains don't resolve
- Retries with new sets of 3 nodes (up to 9 total) on failure

### 🔄 Peer Discovery
Automatic discovery of DNN nodes for resilience:
- Crawls known nodes to discover peers
- Health-checks nodes every 24 hours
- Self-healing node pool (up to 21 nodes)

## Building

```bash
# Windows
go build -o dnn-daemon.exe ./cmd/dnn-daemon

# Linux
GOOS=linux GOARCH=amd64 go build -o dnn-daemon-linux-amd64 ./cmd/dnn-daemon

# macOS (Apple Silicon)
GOOS=darwin GOARCH=arm64 go build -o dnn-daemon-darwin-arm64 ./cmd/dnn-daemon

# macOS (Intel)
GOOS=darwin GOARCH=amd64 go build -o dnn-daemon-darwin-amd64 ./cmd/dnn-daemon
```

## Usage

```bash
# After installation, just use any app normally:
curl https://nabobabout/
firefox https://banana.nabobabout/
```

## Architecture

```
┌────────────────────────┐
│  Any Application       │
│  (browser, curl, etc.) │
└────────────────────────┘
          │
          ▼ DNS query: example2.nabandonaread?
┌───────────────────────────────────────────────┐
│  DNN Daemon                                   │
│  ├─ DNS Capture (WinDivert/TUN)   → Detection │
│  ├─ Resolver (3 nodes parallel)   → Node API  │
│  ├─ Signature Verifier            → Schnorr   │
│  ├─ Cert Verifier                 → PEM match │
│  └─ HTTPS Proxy                   → TLS proxy │
└───────────────────────────────────────────────┘
          │
          ▼ Verified + encrypted connection
┌────────────────────────┐
│  Destination Server    │
└────────────────────────┘
```

## Certificate Verification Flow

```
1. Browser requests https://subdomain.dnnname/
2. Daemon intercepts DNS → returns 127.0.0.1
3. Browser connects to daemon's HTTPS proxy
4. Daemon checks cache for declared cert:
   ├─ Has cert → Generate trusted certificate
   └─ No cert  → Generate untrusted certificate
                 (browser shows security warning)
5. Daemon connects to real server
6. Daemon verifies: server cert == declared cert
7. Proxy established
```

## Configuration

Config file location:
- Windows: `%ProgramData%\DNN\config.yaml`
- Linux: `/etc/dnn/dnn-daemon.yaml`
- macOS: `/usr/local/etc/dnn/dnn-daemon.yaml`

### Example config.yaml

```yaml
nodes:
  - https://node1.example.com
  - https://node2.example.com
```

## Uninstall

Double-click the binary again and choose **Uninstall**, or:

```bash
# Windows (Admin PowerShell)
.\dnn-daemon.exe --uninstall

# Linux/macOS
sudo ./dnn-daemon --uninstall
```

## Package Structure

```
daemon/
├── cmd/dnn-daemon/     # Main entry point
├── internal/
│   ├── ca/             # Certificate Authority & signing
│   ├── capture/        # DNS packet capture (WinDivert/nfqueue)
│   ├── certverify/     # DNN certificate verification
│   ├── config/         # Configuration loading
│   ├── detector/       # DNN pattern detection
│   ├── httpsproxy/     # HTTPS/HTTP interception proxy
│   ├── mapper/         # IPv6 address mapping & cache
│   ├── peerdiscovery/  # Automatic node discovery
│   ├── resolver/       # DNN Node API client
│   └── service/        # Windows/Linux/macOS service management
```

## Troubleshooting

### Windows: Service won't uninstall
If uninstall shows "marked for deletion" error:
```powershell
# Kill any remaining processes manually
wmic process where "name='dnn-daemon.exe'" delete
# Restart computer to complete deletion
```

### Browser shows security warning
This is intentional! The warning appears when:
- Subdomain has no certificate declared in 62600
- Server certificate doesn't match declared certificate
- Certificate DNN ID doesn't match visited domain

Click "Advanced" → "Proceed anyway" to continue (at your own risk).

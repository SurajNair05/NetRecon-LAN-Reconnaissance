<div align="center">

```
  ███╗   ██╗███████╗████████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██╔██╗ ██║█████╗     ██║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██║╚██╗██║██╔══╝     ██║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║ ╚████║███████╗   ██║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
```

**LAN Network Reconnaissance Framework**

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Linux-green?style=flat-square&logo=linux)
![License](https://img.shields.io/badge/License-MIT-yellow?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)
![Requires Root](https://img.shields.io/badge/Requires-Root-red?style=flat-square)
![Version](https://img.shields.io/badge/Version-2.0-cyan?style=flat-square)

*A Metasploit-style terminal framework for ordered LAN reconnaissance — built for pentesters, red teamers, and network security researchers.*

</div>

---

## Overview

NetRecon is a modular, terminal-based LAN reconnaissance tool with a Metasploit-style interactive shell. It is designed around the concept of **ordered operations** — each command builds on the previous one, taking you from network discovery all the way to deep vulnerability scanning in a clean, structured workflow.

Rather than juggling five different tools and manually correlating their output, NetRecon chains everything together in one place:

```
Discover hosts → Identify devices → Deep scan a target → Service modules → Review findings
```

Built during a vacation project by a red teamer, for red teamers.

---

## Features

- **Interactive TUI shell** — Metasploit-style prompt with command history
- **ICMP ping sweep** — Fast multi-threaded sweep across any CIDR range with live progress bar
- **3-layer MAC resolution** — Active Scapy ARP probes → `/proc/net/arp` → OS ARP cache fallback
- **3-layer hostname resolution** — Reverse DNS → NetBIOS (`nmblookup`) → mDNS/Avahi for phones, IoT, Windows boxes
- **Vendor & device identification** — Local OUI table + online macvendors.com fallback for unknown MACs
- **Deep scan engine** — 5-stage pipeline per host:
  - Full 65535-port SYN sweep
  - Service version detection + default scripts
  - OS fingerprinting + traceroute
  - Vulnerability script scan (CVEs, Heartbleed, EternalBlue, etc.)
  - **Port-triggered service modules** (auto-run based on what's open)
- **Port-triggered modules** — 8 specialized modules that fire automatically:
  - HTTP/HTTPS — headers, tech stack, dir brute-force, SSL/TLS audit
  - SSH — auth methods, password auth detection, default credential check
  - FTP — anonymous login, file listing, default credential check
  - SMB — share/user enumeration, MS17-010 EternalBlue check
  - Telnet — banner grab, plaintext warning
  - Database (MySQL/PostgreSQL/MSSQL) — banner, empty password check
  - SNMP — community string brute-force, info dump
  - RDP — NLA enforcement check, BlueKeep CVE-2019-0708 check
- **Rich formatted output** — Color-coded tables, panels, and progress bars
- **Filter & search** — Filter host table by IP, hostname, vendor, or device type

---

## Requirements

- Linux (Kali, Parrot, Ubuntu, or any Debian-based distro)
- Python 3.8+
- nmap installed on the system
- Root privileges (required for raw socket ARP probes and SYN scans)

---

## Installation & Setup

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/netrecon.git
cd netrecon
```

### 2. Install system dependencies

```bash
sudo apt update && sudo apt install nmap -y
```

For NetBIOS and mDNS hostname resolution (optional but recommended — improves device name detection for phones, Windows PCs, and IoT):

```bash
sudo apt install samba-common-bin avahi-utils -y
```

### 3. Create a virtual environment

> **This step is important.** Without a virtual environment, installing packages system-wide on Kali or Parrot may conflict with system Python packages and fail.

```bash
python3 -m venv venv
```

Activate the virtual environment:

```bash
source venv/bin/activate
```

You should see `(venv)` appear at the start of your prompt.

### 4. Install Python dependencies

```bash
pip install -r requirements.txt
```

Or manually:

```bash
pip install scapy rich paramiko
```

> `paramiko` is optional — it enables the SSH default credential check. The tool runs fine without it and will tell you if it's missing.

### 5. Run the tool

> Root is required for ARP probing and SYN scanning. Use `sudo -E` to preserve the virtual environment.

```bash
sudo -E python3 netrecon.py
```

> **Why `sudo -E`?** The `-E` flag tells sudo to keep your current environment variables, which means it uses the Python and packages from your virtual environment instead of the system Python. Without it, sudo falls back to system Python which doesn't have scapy/rich installed.

---

## Usage

Once launched, you will see the interactive NetRecon shell:

```
netrecon>
```

### Workflow (recommended order)

```bash
# Step 1 — Set your target network range
netrecon> set target auto            # auto-detect your local /24 subnet
netrecon> set target 192.168.1.0/24  # or set it manually

# Step 2 — Discover all live hosts on the network
netrecon> scan

# Step 3 — View discovered devices
netrecon> hosts

# Step 4 — Filter hosts (optional)
netrecon> hosts filter apple         # filter by vendor
netrecon> hosts filter 192.168.1     # filter by IP range
netrecon> hosts filter printer       # filter by device type

# Step 5 — Deep scan a specific host (all 5 stages run automatically)
netrecon> info 192.168.1.5
```

### All commands

| Command | Description |
|---|---|
| `set target <CIDR>` | Set the target network range, e.g. `192.168.1.0/24` |
| `set target auto` | Auto-detect and set your local subnet |
| `scan` | Run ICMP ping sweep across the target range |
| `hosts` | Display all discovered hosts in a table |
| `hosts filter <keyword>` | Filter hosts by IP, hostname, vendor, or device type |
| `info <IP>` | Run a full 5-stage deep scan on a specific host |
| `clear` | Clear the screen and redraw the banner |
| `help` | Show the command reference |
| `exit` / `quit` | Exit NetRecon |

---

## Deep Scan — What `info <IP>` Does

Running `info` against a host kicks off a 5-stage pipeline:

```
Stage 1 — Fast port sweep         nmap -sS -p- --min-rate=3000
           ↓ finds all 65535 open TCP ports
Stage 2 — Version + scripts       nmap -sV -sC on open ports
           ↓ exact versions, HTTP titles, SSH keys, SSL certs, etc.
Stage 3 — OS + traceroute         nmap -O --traceroute
           ↓ OS fingerprint, kernel/build guess, hop-by-hop path
Stage 4 — Vuln scripts            nmap --script=vuln
           ↓ known CVEs, Heartbleed, EternalBlue, Shellshock, etc.
Stage 5 — Port-triggered modules  auto-selected based on open ports
           ↓ deep per-service analysis (HTTP, SSH, FTP, SMB, RDP, etc.)
```

### Port-Triggered Modules (Stage 5)

These fire automatically when the corresponding port is found open:

| Port(s) | Module | What it checks |
|---|---|---|
| 80, 443, 8080, 8443 | **HTTP/HTTPS** | Page title, server banner, tech stack detection (WordPress/Django/etc), missing security headers (CSP, HSTS, X-Frame-Options), SSL/TLS version, directory brute-force |
| 22, 2222 | **SSH** | Banner, auth methods, password auth enabled?, top-20 default credential check |
| 21, 2121 | **FTP** | Banner, anonymous login test, file listing if anon works, default cred check |
| 445, 139 | **SMB** | Version, workgroup, share enumeration, user enumeration, MS17-010 (EternalBlue) check |
| 23, 2323 | **Telnet** | Banner grab, plaintext credential warning |
| 3306, 5432, 1433, 27017 | **Database** | Banner, empty password check via nmap scripts |
| 161 | **SNMP** | Community string brute-force (public/private/etc), system info dump |
| 3389 | **RDP** | NLA enforcement check, BlueKeep (CVE-2019-0708) check |

> A full deep scan typically takes **3–8 minutes** per host depending on the number of open ports and which service modules trigger. This is normal.

---

## Example Output

```
╭──────────────  Deep Scan Report — 192.168.1.5  ──────────────╮
│  IP Address    192.168.1.5                                    │
│  Hostname      desktop.local                                  │
│  MAC           aa:bb:cc:dd:ee:ff                              │
│  Vendor        Dell                                           │
│  Device Type   💻  Dell Device                                │
│  Scan Time     94.3s                                          │
╰───────────────────────────────────────────────────────────────╯

OS Fingerprint: Windows 10 Pro (97%)

 Port   Service   Version
 22     ssh       OpenSSH 8.4p1
 80     http      nginx 1.18.0
 445    smb       Windows 10 SMB
 3389   rdp       Microsoft Terminal Services

⚠ Vulnerability Findings
 445/tcp  ms17-010  State: VULNERABLE  Risk: Critical

── SSH — Port 22 ──────────────────────────────────────────────
  Banner         SSH-2.0-OpenSSH_8.4p1
  Password Auth  ENABLED ⚠
  Default Creds  root:root  ⚠ CRITICAL

── SMB — Port 445 ─────────────────────────────────────────────
  Workgroup      WORKGROUP
  Shares         ADMIN$, IPC$, Users
  MS17-010       VULNERABLE ⚠

── RDP — Port 3389 ────────────────────────────────────────────
  NLA Enforced   No — auth bypass risk ⚠
  BlueKeep       Not detected ✓
```

---

## Project Structure

```
netrecon/
├── netrecon.py        # Main tool — all modules in one file (~1700 lines)
├── requirements.txt   # Python dependencies
└── README.md          # This file
```

---

## Requirements File

```
scapy>=2.5.0
rich>=13.0.0
paramiko>=3.0.0
```

---

## Roadmap

Planned modules for future releases:

- [ ] Export results (`export hosts.csv`, `export report.html`)
- [ ] Session save/load — persist scan results between runs
- [ ] ARP spoofing detector — identify MITM attempts on the LAN
- [ ] Device change monitor — alert when new devices appear/disappear
- [ ] Network topology map — ASCII diagram of devices and roles
- [ ] Custom nmap script selection
- [ ] HTTPS certificate chain analysis

---

## Troubleshooting

**`Permission denied` or `Operation not permitted`**
Make sure you are running with `sudo -E`. Raw sockets and SYN scans require root.

**`scapy` not found after activating venv with sudo**
Use `sudo -E python3 netrecon.py` — the `-E` flag preserves your virtual environment. Without it, sudo uses the system Python which does not have scapy installed.

**`paramiko not installed — skipping SSH cred check`**
Run `pip install paramiko` inside your venv, then re-run with `sudo -E`.

**MAC / vendor showing as Unknown**
The tool sends a live ARP probe, but some devices (especially VMs or firewalled devices) block ARP. This is expected for those devices.

**Hostname showing as `—`**
The device may not have a PTR DNS record and may not respond to NetBIOS or mDNS queries. Common on phones with privacy/MAC randomization enabled.

**nmap not found**
Install it: `sudo apt install nmap -y`

**Stage 5 modules not running**
Modules only trigger when their specific ports are found open in Stage 1. If a service is on a non-standard port, the module won't trigger automatically.

---

## ⚠️ Disclaimer

**This tool is intended for use on networks and systems you own or have explicit written permission to test.**

Unauthorized scanning, probing, or enumeration of networks, devices, or systems that you do not own or do not have permission to test is **illegal** in most jurisdictions and may violate computer fraud and abuse laws including but not limited to:

- The Computer Fraud and Abuse Act (CFAA) — United States
- The Computer Misuse Act — United Kingdom
- The Information Technology Act — India
- Similar laws in your country or region

The author of this tool accepts **no responsibility or liability** for any misuse, damage, or legal consequences resulting from the use of this software. By using NetRecon, you agree that:

1. You will only run this tool against networks and devices you own or have explicit authorization to test.
2. You understand that active scanning generates network traffic that may be logged by network administrators.
3. You take full responsibility for your own actions.

**Use responsibly. Hack ethically. Stay legal.**

---

<div align="center">

Built with Python · Scapy · Rich · nmap · For educational and authorized security testing only

</div>

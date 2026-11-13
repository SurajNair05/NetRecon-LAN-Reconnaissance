#!/usr/bin/env python3
"""
NetRecon - LAN Network Reconnaissance Tool
Metasploit-style TUI for ordered network operations
Run with: sudo python3 netrecon.py
"""

import os
import sys
import socket
import struct
import ipaddress
import threading
import subprocess
import time
import re
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.prompt import Prompt
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.live import Live
from rich.columns import Columns
from rich import box

console = Console()

# ─── Banner ────────────────────────────────────────────────────────────────────

BANNER = """
[bold cyan]
  ███╗   ██╗███████╗████████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██╔██╗ ██║█████╗     ██║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██║╚██╗██║██╔══╝     ██║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║ ╚████║███████╗   ██║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
[/bold cyan]
[dim]  LAN Network Reconnaissance Framework  |  v2.0  |  For authorized use only[/dim]
"""

# ─── Globals ───────────────────────────────────────────────────────────────────

session = {
    "target_range": None,
    "discovered_hosts": [],   # list of dicts: {ip, mac, hostname, vendor, status}
    "scan_time": None,
    "interface": None,
}

# Known OUI vendor prefixes (mac prefix -> vendor name)
OUI_TABLE = {
    "00:50:56": "VMware",
    "00:0c:29": "VMware",
    "00:1a:11": "Google",
    "b8:27:eb": "Raspberry Pi",
    "dc:a6:32": "Raspberry Pi",
    "e4:5f:01": "Raspberry Pi",
    "00:17:88": "Philips Hue",
    "18:b4:30": "Nest Labs",
    "44:65:0d": "Amazon",
    "fc:65:de": "Amazon",
    "00:1b:63": "Apple",
    "00:1f:f3": "Apple",
    "00:23:12": "Apple",
    "00:26:b9": "Dell",
    "00:14:22": "Dell",
    "00:1a:a0": "Dell",
    "00:1d:09": "Dell",
    "00:21:9b": "Dell",
    "00:24:e8": "Dell",
    "fc:3f:db": "Apple",
    "a4:c3:f0": "Apple",
    "00:25:00": "Apple",
    "00:26:4a": "Apple",
    "28:cf:da": "Apple",
    "3c:07:54": "Apple",
    "70:56:81": "Apple",
    "ac:87:a3": "Apple",
    "d0:23:db": "Apple",
    "f0:18:98": "Apple",
    "00:1c:bf": "Samsung",
    "00:1d:25": "Samsung",
    "00:1e:e1": "Samsung",
    "00:1f:cc": "Samsung",
    "00:21:19": "Samsung",
    "00:23:39": "Samsung",
    "38:aa:3c": "Samsung",
    "00:1a:73": "Sony",
    "00:1d:0d": "Sony",
    "00:19:cb": "Sony",
    "00:24:be": "Sony",
    "00:01:e3": "Cisco",
    "00:02:17": "Cisco",
    "00:03:6b": "Cisco",
    "00:04:9a": "Cisco",
    "00:06:28": "Cisco",
    "00:1a:6c": "Cisco",
    "74:86:7a": "Cisco",
    "00:15:5d": "Microsoft Hyper-V",
    "00:03:ff": "Microsoft",
    "00:0d:3a": "Microsoft",
    "00:12:5a": "HP",
    "00:17:a4": "HP",
    "00:1b:78": "HP",
    "00:1e:0b": "HP",
    "00:21:5a": "HP",
    "00:22:64": "HP",
    "00:23:7d": "HP",
    "00:24:81": "HP",
    "00:26:55": "HP",
    "1c:c1:de": "HP",
    "00:1c:c0": "Canon",
    "00:1e:8f": "Canon",
    "00:21:b7": "Canon",
    "00:26:2d": "Canon",
    "00:0a:e4": "Epson",
    "00:26:ab": "Epson",
    "00:04:20": "Epson",
    "10:6f:3f": "Netgear",
    "20:4e:7f": "Netgear",
    "2c:b0:5d": "Netgear",
    "30:46:9a": "Netgear",
    "44:94:fc": "Netgear",
    "9c:d3:6d": "Netgear",
    "a0:21:b7": "Netgear",
    "c0:3f:0e": "Netgear",
    "e0:91:f5": "Netgear",
    "00:18:e7": "TP-Link",
    "00:1d:0f": "TP-Link",
    "14:cc:20": "TP-Link",
    "50:c7:bf": "TP-Link",
    "54:af:97": "TP-Link",
    "74:ea:3a": "TP-Link",
    "8c:21:0a": "TP-Link",
    "ac:84:c6": "TP-Link",
    "c4:e9:84": "TP-Link",
    "f4:f2:6d": "TP-Link",
}

DEVICE_TYPE_HINTS = {
    "Apple":         "💻 / 📱  Apple Device",
    "Samsung":       "📱  Samsung Device",
    "Sony":          "📺  Sony Device",
    "Raspberry Pi":  "🖥️   Raspberry Pi",
    "Cisco":         "🌐  Cisco Network Device",
    "TP-Link":       "📡  TP-Link Router/AP",
    "Netgear":       "📡  Netgear Router/AP",
    "HP":            "🖨️   HP Printer/PC",
    "Canon":         "🖨️   Canon Printer",
    "Epson":         "🖨️   Epson Printer",
    "Dell":          "💻  Dell Device",
    "Microsoft":     "💻  Microsoft/Windows Device",
    "VMware":        "🖥️   Virtual Machine",
    "Amazon":        "🔊  Amazon Device (Echo/Fire)",
    "Google":        "🔊  Google Device",
    "Philips Hue":   "💡  Philips Hue",
    "Nest Labs":     "🏠  Nest Smart Device",
}

# ─── Helpers ───────────────────────────────────────────────────────────────────

def get_local_ip_and_iface():
    """Detect local IP and default interface."""
    try:
        result = subprocess.run(
            ["ip", "route", "get", "8.8.8.8"],
            capture_output=True, text=True
        )
        for part in result.stdout.split():
            if re.match(r'\d+\.\d+\.\d+\.\d+', part):
                local_ip = part
                break
        iface_match = re.search(r'dev\s+(\S+)', result.stdout)
        iface = iface_match.group(1) if iface_match else "eth0"
        return local_ip, iface
    except Exception:
        return "127.0.0.1", "eth0"

def get_subnet_from_ip(ip):
    """Auto-detect /24 subnet from local IP."""
    parts = ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"

def get_mac_scapy(ip, iface=None, timeout=2):
    """
    Send a live ARP Who-has request using Scapy.
    This is the most reliable method — works even if ARP cache is empty.
    """
    try:
        from scapy.all import ARP, Ether, srp, conf
        conf.verb = 0
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        kwargs = {"timeout": timeout, "verbose": False}
        if iface:
            kwargs["iface"] = iface
        answered, _ = srp(pkt, **kwargs)
        if answered:
            return answered[0][1].hwsrc.lower()
    except Exception:
        pass
    return None

def get_mac_from_arp_cache(ip):
    """Fallback: read OS ARP cache (works if host was already contacted)."""
    try:
        result = subprocess.run(
            ["arp", "-n", ip], capture_output=True, text=True
        )
        match = re.search(r'(([0-9a-f]{2}[:\-]){5}[0-9a-f]{2})', result.stdout, re.IGNORECASE)
        return match.group(1).lower() if match else None
    except Exception:
        return None

def get_mac_from_neighbor(ip):
    """Fallback: read /proc/net/arp directly."""
    try:
        with open("/proc/net/arp") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 4 and parts[0] == ip:
                    mac = parts[3]
                    if mac != "00:00:00:00:00:00":
                        return mac.lower()
    except Exception:
        pass
    return None

def get_mac(ip, iface=None):
    """Try all methods to get MAC: Scapy ARP → /proc/net/arp → arp cache."""
    mac = get_mac_scapy(ip, iface=iface)
    if mac:
        return mac
    mac = get_mac_from_neighbor(ip)
    if mac:
        return mac
    return get_mac_from_arp_cache(ip)

# Online OUI lookup cache to avoid hammering the API
_oui_cache = {}

def lookup_vendor_online(mac):
    """Query macvendors.com API for vendor — used when local OUI table misses."""
    if not mac:
        return None
    prefix = mac[:8].replace(":", "-").upper()
    if prefix in _oui_cache:
        return _oui_cache[prefix]
    try:
        url = f"https://api.macvendors.com/{urllib.parse.quote(mac[:8])}"
        req = urllib.request.Request(url, headers={"User-Agent": "NetRecon/1.0"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            vendor = resp.read().decode().strip()
            if vendor and len(vendor) < 60:
                _oui_cache[prefix] = vendor
                return vendor
    except Exception:
        pass
    return None

def lookup_vendor(mac, online=True):
    """Lookup vendor from MAC: local OUI table first, then online fallback."""
    if not mac:
        return "Unknown"
    prefix = mac[:8].lower()
    local = OUI_TABLE.get(prefix)
    if local:
        return local
    if online:
        result = lookup_vendor_online(mac)
        if result:
            return result
    return "Unknown"

def resolve_hostname(ip, timeout=1.5):
    """
    Try multiple methods to get a hostname:
    1. Reverse DNS (standard)
    2. NetBIOS name query (Windows PCs, printers)
    3. mDNS .local lookup (phones, macs, IoT)
    """
    # 1. Reverse DNS
    try:
        socket.setdefaulttimeout(timeout)
        hostname = socket.gethostbyaddr(ip)[0]
        if hostname and hostname != ip:
            return hostname
    except Exception:
        pass

    # 2. NetBIOS via nmblookup (common on Kali)
    try:
        result = subprocess.run(
            ["nmblookup", "-A", ip],
            capture_output=True, text=True, timeout=2
        )
        for line in result.stdout.splitlines():
            line = line.strip()
            if "<00>" in line and "<GROUP>" not in line:
                name = line.split()[0].strip()
                if name and name != ip:
                    return name.upper()
    except Exception:
        pass

    # 3. mDNS via avahi-resolve (phones, Macs, IoT announce .local)
    try:
        result = subprocess.run(
            ["avahi-resolve", "--address", ip],
            capture_output=True, text=True, timeout=2
        )
        out = result.stdout.strip()
        if out:
            parts = out.split()
            if len(parts) >= 2:
                return parts[1].rstrip(".")
    except Exception:
        pass

    return None

def ping_host(ip, timeout=1):
    """ICMP ping via system ping command."""
    try:
        result = subprocess.run(
            ["ping", "-c", "1", "-W", str(timeout), str(ip)],
            capture_output=True, text=True
        )
        return result.returncode == 0
    except Exception:
        return False

def get_device_type(vendor):
    return DEVICE_TYPE_HINTS.get(vendor, "❓  Unknown Device")

# ─── Scan Engine ──────────────────────────────────────────────────────────────

def icmp_sweep(target_range, progress_callback=None):
    """
    ICMP ping sweep over a CIDR range.
    Returns list of alive IPs.
    """
    try:
        network = ipaddress.ip_network(target_range, strict=False)
    except ValueError as e:
        console.print(f"[red]  Invalid range: {e}[/red]")
        return []

    hosts = list(network.hosts())
    alive = []
    lock = threading.Lock()

    def check(ip):
        if ping_host(str(ip)):
            with lock:
                alive.append(str(ip))
        if progress_callback:
            progress_callback()

    with ThreadPoolExecutor(max_workers=80) as executor:
        futures = [executor.submit(check, ip) for ip in hosts]
        for f in as_completed(futures):
            pass

    return sorted(alive, key=lambda x: [int(o) for o in x.split('.')])

def enrich_host(ip):
    """
    For a live IP: send ARP probe to get MAC, then vendor, hostname, device type.
    Returns a host dict.
    """
    iface = session.get("interface")
    mac = get_mac(ip, iface=iface)
    vendor = lookup_vendor(mac) if mac else "Unknown"
    hostname = resolve_hostname(ip)
    device_type = get_device_type(vendor)
    return {
        "ip": ip,
        "mac": mac or "??:??:??:??:??:??",
        "hostname": hostname or "—",
        "vendor": vendor,
        "device_type": device_type,
        "status": "alive",
    }

# ─── TUI Screens ──────────────────────────────────────────────────────────────

def print_banner():
    console.clear()
    console.print(BANNER)
    console.print()

def print_status_bar():
    local_ip, iface = get_local_ip_and_iface()
    session["interface"] = iface
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    status = Text()
    status.append(f"  Interface: ", style="dim")
    status.append(iface, style="bold cyan")
    status.append(f"  |  Local IP: ", style="dim")
    status.append(local_ip, style="bold cyan")
    if session["target_range"]:
        status.append(f"  |  Target: ", style="dim")
        status.append(session["target_range"], style="bold yellow")
    if session["discovered_hosts"]:
        status.append(f"  |  Hosts: ", style="dim")
        status.append(str(len(session["discovered_hosts"])), style="bold green")
    status.append(f"  |  {now}", style="dim")
    console.print(Panel(status, box=box.SIMPLE, padding=(0, 1)))

def print_help():
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("Command", style="bold cyan", width=22)
    table.add_column("Description", style="white")

    commands = [
        ("set target <CIDR>",   "Set target network range  e.g. 192.168.1.0/24"),
        ("set target auto",     "Auto-detect local subnet"),
        ("scan",                "Run ICMP ping sweep on target"),
        ("hosts",               "Show all discovered hosts"),
        ("hosts filter <kw>",   "Filter hosts by IP, name, or vendor"),
        ("info <IP>",           "Deep scan a host — ports, services, OS, vulns"),
        ("clear",               "Clear the screen"),
        ("help",                "Show this help menu"),
        ("exit / quit",         "Exit NetRecon"),
    ]
    for cmd, desc in commands:
        table.add_row(f"  {cmd}", desc)

    console.print(Panel(
        table,
        title="[bold cyan]Available Commands[/bold cyan]",
        border_style="cyan",
        padding=(1, 2)
    ))

def print_hosts(hosts, title="Discovered Hosts", filter_kw=None):
    if not hosts:
        console.print("[yellow]  No hosts discovered yet. Run [bold]scan[/bold] first.[/yellow]")
        return

    display = hosts
    if filter_kw:
        kw = filter_kw.lower()
        display = [h for h in hosts if (
            kw in h["ip"] or
            kw in h["hostname"].lower() or
            kw in h["vendor"].lower() or
            kw in h["device_type"].lower()
        )]
        if not display:
            console.print(f"[yellow]  No hosts matched '[bold]{filter_kw}[/bold]'[/yellow]")
            return

    table = Table(
        title=f"[bold cyan]{title}[/bold cyan]  [dim]({len(display)} host{'s' if len(display)!=1 else ''})[/dim]",
        box=box.ROUNDED,
        border_style="cyan",
        show_lines=False,
        padding=(0, 1),
        header_style="bold cyan",
    )
    table.add_column("#",           style="dim",        width=4,  justify="right")
    table.add_column("IP Address",  style="bold white", width=17)
    table.add_column("MAC Address", style="dim cyan",   width=20)
    table.add_column("Hostname",    style="green",      width=28)
    table.add_column("Vendor",      style="yellow",     width=16)
    table.add_column("Device Type", style="white",      width=28)
    table.add_column("Status",      style="green",      width=8)

    for i, h in enumerate(display, 1):
        table.add_row(
            str(i),
            h["ip"],
            h["mac"],
            h["hostname"],
            h["vendor"],
            h["device_type"],
            "[bold green]● alive[/bold green]",
        )

    console.print()
    console.print(table)
    console.print()

# ─── Port-Triggered Module Engines ───────────────────────────────────────────

# ── Top-20 default credential list ───────────────────────────────────────────
DEFAULT_CREDS = [
    ("admin",     "admin"),
    ("admin",     ""),
    ("admin",     "password"),
    ("admin",     "1234"),
    ("admin",     "12345"),
    ("root",      "root"),
    ("root",      ""),
    ("root",      "toor"),
    ("root",      "password"),
    ("root",      "alpine"),
    ("pi",        "raspberry"),
    ("user",      "user"),
    ("user",      "password"),
    ("guest",     "guest"),
    ("guest",     ""),
    ("test",      "test"),
    ("support",   "support"),
    ("ubnt",      "ubnt"),
    ("admin",     "admin123"),
    ("administrator", "password"),
]

# ── HTTP/HTTPS Module ─────────────────────────────────────────────────────────

HTTP_WORDLIST = [
    "admin", "login", "dashboard", "console", "manage", "manager",
    "administrator", "wp-admin", "phpmyadmin", "webadmin", "config",
    "setup", "install", "backup", "db", "database", "api", "v1", "v2",
    "test", "dev", "staging", "old", "new", "tmp", "temp", "upload",
    "uploads", "files", "images", "static", "assets", "js", "css",
    "index.php", "index.html", "robots.txt", "sitemap.xml",
    ".env", ".git", "web.config", "info.php", "phpinfo.php",
    "shell.php", "cmd.php", "server-status", "server-info",
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]

def http_module(ip, ports):
    """
    HTTP/HTTPS module — runs when port 80/443/8080/8443 found open.
    Checks: headers, tech stack, title, security headers, dir brute.
    """
    results = {}
    http_ports = [p for p in ports if p["port"] in ("80","443","8080","8443","8888","8000","8888","5000","3000")]
    if not http_ports:
        return results

    console.print("  [cyan]HTTP[/cyan]  Web service analysis")

    for p in http_ports:
        port_num = p["port"]
        scheme   = "https" if port_num in ("443","8443") else "http"
        base_url = f"{scheme}://{ip}:{port_num}"
        entry    = {"port": port_num, "scheme": scheme}

        # ── Fetch root page ───────────────────────────────────────────────
        try:
            ctx = None
            if scheme == "https":
                import ssl
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
            req = urllib.request.Request(
                f"{base_url}/",
                headers={"User-Agent": "Mozilla/5.0 NetRecon/1.0"}
            )
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                raw_headers = dict(resp.headers)
                body        = resp.read(4096).decode("utf-8", errors="ignore")
                entry["status_code"] = resp.status

                # Page title
                title_m = re.search(r'<title[^>]*>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
                entry["title"] = title_m.group(1).strip()[:80] if title_m else "—"

                # Server header
                entry["server"] = raw_headers.get("Server", raw_headers.get("server", "—"))

                # Tech stack hints
                tech = []
                powered = raw_headers.get("X-Powered-By", raw_headers.get("x-powered-by", ""))
                if powered:
                    tech.append(powered)
                for sig, name in [
                    ("wp-content",    "WordPress"),
                    ("wp-json",       "WordPress"),
                    ("joomla",        "Joomla"),
                    ("drupal",        "Drupal"),
                    ("laravel",       "Laravel"),
                    ("django",        "Django"),
                    ("rails",         "Ruby on Rails"),
                    ("react",         "React"),
                    ("angular",       "Angular"),
                    ("vue",           "Vue.js"),
                    ("phpmyadmin",    "phpMyAdmin"),
                    ("grafana",       "Grafana"),
                    ("jenkins",       "Jenkins"),
                    ("tomcat",        "Apache Tomcat"),
                    ("mikrotik",      "MikroTik"),
                    ("ubiquiti",      "Ubiquiti"),
                    ("synology",      "Synology NAS"),
                    ("qnap",          "QNAP NAS"),
                    ("hikvision",     "Hikvision Camera"),
                    ("dahua",         "Dahua Camera"),
                ]:
                    if sig in body.lower() or sig in str(raw_headers).lower():
                        tech.append(name)
                entry["tech"] = list(dict.fromkeys(tech))  # dedupe

                # Security headers audit
                missing_headers = [h for h in SECURITY_HEADERS if h not in raw_headers and h.lower() not in raw_headers]
                entry["missing_security_headers"] = missing_headers

                # SSL cert info
                if scheme == "https":
                    try:
                        import ssl as ssl_mod
                        conn = ssl_mod.create_default_context()
                        conn.check_hostname = False
                        conn.verify_mode    = ssl_mod.CERT_NONE
                        with conn.wrap_socket(
                            socket.create_connection((ip, int(port_num)), timeout=3),
                            server_hostname=ip
                        ) as ssock:
                            cert = ssock.getpeercert()
                            entry["ssl_subject"] = dict(x[0] for x in cert.get("subject", []))
                            entry["ssl_issuer"]  = dict(x[0] for x in cert.get("issuer", []))
                            entry["ssl_expires"] = cert.get("notAfter", "—")
                            # TLS version
                            entry["tls_version"] = ssock.version()
                    except Exception:
                        pass

        except Exception as e:
            entry["error"] = str(e)[:80]

        # ── Directory brute-force (lightweight) ───────────────────────────
        found_paths = []
        def check_path(word):
            try:
                url = f"{base_url}/{word}"
                ctx2 = None
                if scheme == "https":
                    import ssl
                    ctx2 = ssl.create_default_context()
                    ctx2.check_hostname = False
                    ctx2.verify_mode    = ssl.CERT_NONE
                req2 = urllib.request.Request(
                    url, headers={"User-Agent": "Mozilla/5.0 NetRecon/1.0"}
                )
                with urllib.request.urlopen(req2, timeout=3, context=ctx2) as r:
                    if r.status in (200, 301, 302, 403):
                        found_paths.append((word, r.status))
            except urllib.error.HTTPError as e:
                if e.code in (401, 403):
                    found_paths.append((word, e.code))
            except Exception:
                pass

        with ThreadPoolExecutor(max_workers=15) as ex:
            list(ex.map(check_path, HTTP_WORDLIST))

        entry["found_paths"] = sorted(found_paths, key=lambda x: x[1])
        results[port_num] = entry

    return results


# ── SSH Module ────────────────────────────────────────────────────────────────

def ssh_module(ip, ports):
    """SSH module — banner grab, auth methods, default cred check."""
    ssh_ports = [p for p in ports if p["port"] in ("22","2222","22222")]
    if not ssh_ports:
        return {}

    console.print("  [cyan]SSH[/cyan]   SSH analysis")
    results = {}

    for p in ssh_ports:
        port_num = int(p["port"])
        entry    = {"port": str(port_num)}

        # Banner grab
        try:
            s = socket.create_connection((ip, port_num), timeout=3)
            banner = s.recv(256).decode("utf-8", errors="ignore").strip()
            s.close()
            entry["banner"] = banner
        except Exception:
            entry["banner"] = "—"

        # Auth methods via ssh -v
        try:
            res = subprocess.run(
                ["ssh", "-v", "-o", "BatchMode=yes",
                 "-o", "ConnectTimeout=3",
                 "-o", "StrictHostKeyChecking=no",
                 "-p", str(port_num), f"root@{ip}"],
                capture_output=True, text=True, timeout=6
            )
            out = res.stderr
            methods = re.findall(r'Authentications that can continue: (.+)', out)
            entry["auth_methods"] = methods[0].split(",") if methods else ["unknown"]
            entry["password_auth"] = "password" in out.lower()
        except Exception:
            entry["auth_methods"] = ["unknown"]
            entry["password_auth"] = False

        # Default cred check (only if password auth is enabled)
        cred_hits = []
        if entry.get("password_auth"):
            try:
                import paramiko
                for user, pwd in DEFAULT_CREDS:
                    try:
                        c = paramiko.SSHClient()
                        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                        c.connect(ip, port=port_num, username=user,
                                  password=pwd, timeout=3, banner_timeout=5)
                        cred_hits.append((user, pwd))
                        c.close()
                        break  # stop on first hit
                    except Exception:
                        pass
            except ImportError:
                entry["cred_note"] = "paramiko not installed — skipping SSH cred check (pip install paramiko)"
        entry["cred_hits"] = cred_hits

        results[str(port_num)] = entry

    return results


# ── FTP Module ────────────────────────────────────────────────────────────────

def ftp_module(ip, ports):
    """FTP module — banner, anonymous login, file listing."""
    ftp_ports = [p for p in ports if p["port"] in ("21","2121")]
    if not ftp_ports:
        return {}

    console.print("  [cyan]FTP[/cyan]   FTP analysis")
    results = {}

    for p in ftp_ports:
        port_num = int(p["port"])
        entry    = {"port": str(port_num)}
        import ftplib

        # Banner
        try:
            ftp = ftplib.FTP()
            ftp.connect(ip, port_num, timeout=5)
            entry["banner"] = ftp.getwelcome()
        except Exception as e:
            entry["banner"] = "—"
            results[str(port_num)] = entry
            continue

        # Anonymous login
        try:
            ftp.login("anonymous", "netrecon@test.com")
            entry["anonymous_login"] = True
            listing = []
            ftp.retrlines("LIST", listing.append)
            entry["file_listing"] = listing[:20]
        except Exception:
            entry["anonymous_login"] = False
            entry["file_listing"] = []

        # Default cred check
        cred_hits = []
        if not entry["anonymous_login"]:
            for user, pwd in DEFAULT_CREDS[:10]:
                try:
                    ftp2 = ftplib.FTP()
                    ftp2.connect(ip, port_num, timeout=3)
                    ftp2.login(user, pwd)
                    cred_hits.append((user, pwd))
                    ftp2.quit()
                    break
                except Exception:
                    pass
        entry["cred_hits"] = cred_hits

        try:
            ftp.quit()
        except Exception:
            pass

        results[str(port_num)] = entry

    return results


# ── SMB Module ────────────────────────────────────────────────────────────────

def smb_module(ip, ports):
    """SMB module — version, null session, shares, MS17-010 hint."""
    smb_ports = [p for p in ports if p["port"] in ("445","139")]
    if not smb_ports:
        return {}

    console.print("  [cyan]SMB[/cyan]   SMB analysis")
    results = {}

    # Use nmap scripts for SMB (most reliable)
    out = run_nmap(ip, [
        "--script=smb-security-mode,smb2-security-mode,smb-vuln-ms17-010,"
        "smb-enum-shares,smb-enum-users,smb-os-discovery",
        "-p445,139", "-T4"
    ], timeout=60)

    # Parse security mode
    sec_mode = re.findall(r'(message_signing|account_used|authentication_level)[^\n]+', out)
    shares    = re.findall(r'\\\\\S+\\(\S+)\s+(?:Disk|IPC|Print)', out)
    users     = re.findall(r'user:\s*(\S+)', out, re.IGNORECASE)
    os_disc   = re.findall(r'OS:\s*(.+)', out)
    ms17      = "VULNERABLE" in out and "ms17-010" in out.lower()
    workgroup = re.findall(r'Workgroup:\s*(\S+)', out, re.IGNORECASE)

    results["445"] = {
        "port":         "445",
        "raw":          out,
        "security":     sec_mode,
        "shares":       list(set(shares)),
        "users":        list(set(users))[:10],
        "os_discovery": os_disc[:2],
        "ms17_010":     ms17,
        "workgroup":    workgroup[0] if workgroup else "—",
    }

    return results


# ── Telnet Module ─────────────────────────────────────────────────────────────

def telnet_module(ip, ports):
    """Telnet module — banner grab + default cred check."""
    tel_ports = [p for p in ports if p["port"] in ("23","2323")]
    if not tel_ports:
        return {}

    console.print("  [cyan]TELNET[/cyan] Telnet analysis")
    results = {}

    for p in tel_ports:
        port_num = int(p["port"])
        entry    = {"port": str(port_num)}

        # Banner
        try:
            s = socket.create_connection((ip, port_num), timeout=4)
            s.settimeout(3)
            banner = b""
            try:
                while True:
                    chunk = s.recv(256)
                    if not chunk:
                        break
                    banner += chunk
                    if len(banner) > 512:
                        break
            except Exception:
                pass
            s.close()
            entry["banner"] = banner.decode("utf-8", errors="ignore").strip()[:200]
        except Exception:
            entry["banner"] = "—"

        # Default creds via nmap telnet scripts
        out = run_nmap(ip, [
            "--script=telnet-ntlm-info,telnet-encryption",
            f"-p{port_num}", "-T4"
        ], timeout=30)
        entry["nmap_info"] = out

        results[str(port_num)] = entry

    return results


# ── MySQL Module ──────────────────────────────────────────────────────────────

def mysql_module(ip, ports):
    """MySQL/PostgreSQL module — banner + default cred check."""
    db_ports = [p for p in ports if p["port"] in ("3306","5432","1433","1521","27017")]
    if not db_ports:
        return {}

    console.print("  [cyan]DB[/cyan]    Database service analysis")
    results = {}

    for p in db_ports:
        port_num = int(p["port"])
        entry    = {"port": str(port_num), "service": p["service"]}

        # Banner via socket
        try:
            s = socket.create_connection((ip, port_num), timeout=3)
            banner = s.recv(256)
            s.close()
            entry["banner"] = banner.decode("utf-8", errors="ignore").strip()[:100]
        except Exception:
            entry["banner"] = "—"

        # Nmap db scripts
        script_map = {
            "3306": "mysql-info,mysql-empty-password,mysql-databases",
            "5432": "pgsql-brute",
            "1433": "ms-sql-info,ms-sql-empty-password",
            "27017": "mongodb-info",
        }
        script = script_map.get(str(port_num), "")
        if script:
            out = run_nmap(ip, [f"--script={script}", f"-p{port_num}", "-T4"], timeout=40)
            entry["nmap_info"] = out
            entry["empty_password"] = "empty" in out.lower() or "allowed" in out.lower()

        results[str(port_num)] = entry

    return results


# ── SNMP Module ───────────────────────────────────────────────────────────────

def snmp_module(ip, ports):
    """SNMP module — community string check + info dump."""
    snmp_ports = [p for p in ports if p["port"] == "161"]
    if not snmp_ports:
        return {}

    console.print("  [cyan]SNMP[/cyan]  SNMP analysis")

    out = run_nmap(ip, [
        "--script=snmp-info,snmp-sysdescr,snmp-interfaces,snmp-netstat",
        "-sU", "-p161", "-T4"
    ], timeout=45)

    community_hits = []
    for community in ["public", "private", "community", "snmp", "manager", "admin"]:
        try:
            res = subprocess.run(
                ["snmpwalk", "-v2c", "-c", community, ip, "1.3.6.1.2.1.1.1.0"],
                capture_output=True, text=True, timeout=4
            )
            if res.returncode == 0 and res.stdout.strip():
                community_hits.append(community)
                break
        except Exception:
            pass

    return {"161": {
        "port": "161",
        "nmap_info": out,
        "community_hits": community_hits,
    }}


# ── RDP Module ────────────────────────────────────────────────────────────────

def rdp_module(ip, ports):
    """RDP module — NLA check, BlueKeep hint."""
    rdp_ports = [p for p in ports if p["port"] in ("3389","3388")]
    if not rdp_ports:
        return {}

    console.print("  [cyan]RDP[/cyan]   RDP analysis")

    out = run_nmap(ip, [
        "--script=rdp-enum-encryption,rdp-vuln-ms12-020",
        "-p3389", "-T4"
    ], timeout=40)

    bluekeep_out = run_nmap(ip, [
        "--script=rdp-vuln-ms12-020",
        "-p3389", "-T4"
    ], timeout=30)

    nla_enabled = "NLA" in out or "CredSSP" in out
    bluekeep    = "VULNERABLE" in bluekeep_out

    return {"3389": {
        "port":      "3389",
        "nmap_info": out,
        "nla":       nla_enabled,
        "bluekeep":  bluekeep,
    }}


# ── Render module results ─────────────────────────────────────────────────────

def print_module_results(all_module_results):
    """Render all port-triggered module results in order."""

    # HTTP results
    http_res = all_module_results.get("http", {})
    if http_res:
        for port_num, e in http_res.items():
            title_str  = f"[bold cyan]  HTTP/HTTPS — Port {port_num}  [/bold cyan]"
            rows = []
            rows.append(("URL",          f"{e['scheme']}://<ip>:{port_num}"))
            rows.append(("Status Code",  str(e.get("status_code","—"))))
            rows.append(("Page Title",   e.get("title","—")))
            rows.append(("Server",       e.get("server","—")))
            if e.get("tech"):
                rows.append(("Tech Stack", ", ".join(e["tech"])))
            if e.get("tls_version"):
                rows.append(("TLS Version", e["tls_version"]))
            if e.get("ssl_expires"):
                rows.append(("Cert Expires", e["ssl_expires"]))

            t = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
            t.add_column("k", style="bold cyan", width=22)
            t.add_column("v", style="white",     width=55)
            for k, v in rows:
                t.add_row(k, v)

            # Security headers
            missing = e.get("missing_security_headers", [])
            if missing:
                t.add_row("[red]Missing Headers[/red]", "[red]" + ", ".join(missing) + "[/red]")
            else:
                t.add_row("[green]Security Headers[/green]", "[green]All present ✓[/green]")

            console.print(Panel(t, title=title_str, border_style="cyan", padding=(0,0)))

            # Dir brute results
            found = e.get("found_paths", [])
            if found:
                dtable = Table(box=box.ROUNDED, border_style="cyan",
                               header_style="bold cyan", padding=(0,1))
                dtable.add_column("Path",   style="cyan",      width=35)
                dtable.add_column("Status", style="bold white",width=10)
                status_colors = {200:"green", 301:"yellow", 302:"yellow", 403:"red", 401:"red"}
                for word, code in found:
                    col = status_colors.get(code, "white")
                    dtable.add_row(f"/{word}", f"[{col}]{code}[/{col}]")
                console.print(Panel(dtable,
                    title="[bold cyan]  Directory Brute-Force Results  [/bold cyan]",
                    border_style="cyan", padding=(0,0)))
            else:
                console.print("  [dim]HTTP: No interesting paths found.[/dim]")
            console.print()

    # SSH results
    ssh_res = all_module_results.get("ssh", {})
    if ssh_res:
        for port_num, e in ssh_res.items():
            t = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
            t.add_column("k", style="bold cyan", width=22)
            t.add_column("v", style="white",     width=55)
            t.add_row("Banner",       e.get("banner","—")[:80])
            methods = e.get("auth_methods", [])
            t.add_row("Auth Methods", ", ".join(m.strip() for m in methods) if methods else "—")
            pw = e.get("password_auth", False)
            t.add_row("Password Auth", "[bold red]ENABLED ⚠[/bold red]" if pw else "[green]Disabled ✓[/green]")
            hits = e.get("cred_hits", [])
            if hits:
                t.add_row("[bold red]Default Creds[/bold red]",
                          "[bold red]" + ", ".join(f"{u}:{p}" for u,p in hits) + "  ⚠ CRITICAL[/bold red]")
            elif pw:
                t.add_row("Default Creds", "[green]None found ✓[/green]")
            if e.get("cred_note"):
                t.add_row("[dim]Note[/dim]", f"[dim]{e['cred_note']}[/dim]")
            console.print(Panel(t,
                title=f"[bold cyan]  SSH — Port {port_num}  [/bold cyan]",
                border_style="cyan", padding=(0,0)))
            console.print()

    # FTP results
    ftp_res = all_module_results.get("ftp", {})
    if ftp_res:
        for port_num, e in ftp_res.items():
            t = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
            t.add_column("k", style="bold cyan", width=22)
            t.add_column("v", style="white",     width=55)
            t.add_row("Banner", e.get("banner","—")[:80])
            anon = e.get("anonymous_login", False)
            t.add_row("Anonymous Login",
                      "[bold red]ALLOWED ⚠[/bold red]" if anon else "[green]Blocked ✓[/green]")
            hits = e.get("cred_hits", [])
            if hits:
                t.add_row("[bold red]Default Creds[/bold red]",
                          "[bold red]" + ", ".join(f"{u}:{p}" for u,p in hits) + "  ⚠ CRITICAL[/bold red]")
            console.print(Panel(t,
                title=f"[bold cyan]  FTP — Port {port_num}  [/bold cyan]",
                border_style="cyan", padding=(0,0)))
            listing = e.get("file_listing", [])
            if listing:
                console.print("  [yellow]Anonymous FTP listing:[/yellow]")
                for line in listing[:15]:
                    console.print(f"    [dim]{line}[/dim]")
            console.print()

    # SMB results
    smb_res = all_module_results.get("smb", {})
    if smb_res:
        for port_num, e in smb_res.items():
            t = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
            t.add_column("k", style="bold cyan", width=22)
            t.add_column("v", style="white",     width=55)
            if e.get("workgroup") and e["workgroup"] != "—":
                t.add_row("Workgroup",    e["workgroup"])
            if e.get("os_discovery"):
                t.add_row("OS",           e["os_discovery"][0])
            shares = e.get("shares", [])
            t.add_row("Shares",       ", ".join(shares) if shares else "[dim]None found[/dim]")
            users  = e.get("users", [])
            t.add_row("Users",        ", ".join(users)  if users  else "[dim]None found[/dim]")
            ms17   = e.get("ms17_010", False)
            t.add_row("MS17-010 (EternalBlue)",
                      "[bold red]VULNERABLE ⚠[/bold red]" if ms17 else "[green]Not detected ✓[/green]")
            console.print(Panel(t,
                title=f"[bold cyan]  SMB — Port {port_num}  [/bold cyan]",
                border_style="cyan", padding=(0,0)))
            console.print()

    # Telnet results
    tel_res = all_module_results.get("telnet", {})
    if tel_res:
        for port_num, e in tel_res.items():
            t = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
            t.add_column("k", style="bold cyan", width=22)
            t.add_column("v", style="white",     width=55)
            t.add_row("Banner", e.get("banner","—")[:120])
            t.add_row("[bold red]Warning[/bold red]",
                      "[bold red]Telnet is unencrypted — credentials sent in plaintext[/bold red]")
            console.print(Panel(t,
                title=f"[bold cyan]  Telnet — Port {port_num}  [/bold cyan]",
                border_style="red", padding=(0,0)))
            console.print()

    # DB results
    db_res = all_module_results.get("db", {})
    if db_res:
        for port_num, e in db_res.items():
            t = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
            t.add_column("k", style="bold cyan", width=22)
            t.add_column("v", style="white",     width=55)
            t.add_row("Service", e.get("service","—"))
            t.add_row("Banner",  e.get("banner","—")[:80])
            empty = e.get("empty_password", False)
            t.add_row("Empty Password",
                      "[bold red]YES ⚠ CRITICAL[/bold red]" if empty else "[green]No ✓[/green]")
            console.print(Panel(t,
                title=f"[bold cyan]  Database — Port {port_num}  [/bold cyan]",
                border_style="cyan", padding=(0,0)))
            console.print()

    # SNMP results
    snmp_res = all_module_results.get("snmp", {})
    if snmp_res:
        e = snmp_res.get("161", {})
        t = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
        t.add_column("k", style="bold cyan", width=22)
        t.add_column("v", style="white",     width=55)
        hits = e.get("community_hits", [])
        t.add_row("Community Strings",
                  "[bold red]" + ", ".join(hits) + "  ⚠[/bold red]" if hits else "[green]None cracked ✓[/green]")
        console.print(Panel(t,
            title="[bold cyan]  SNMP — Port 161  [/bold cyan]",
            border_style="cyan", padding=(0,0)))
        console.print()

    # RDP results
    rdp_res = all_module_results.get("rdp", {})
    if rdp_res:
        e = rdp_res.get("3389", {})
        t = Table(box=box.SIMPLE, show_header=False, padding=(0,2))
        t.add_column("k", style="bold cyan", width=22)
        t.add_column("v", style="white",     width=55)
        nla = e.get("nla", False)
        t.add_row("NLA Enforced",
                  "[green]Yes ✓[/green]" if nla else "[bold red]No — auth bypassed risk ⚠[/bold red]")
        bk = e.get("bluekeep", False)
        t.add_row("BlueKeep (CVE-2019-0708)",
                  "[bold red]VULNERABLE ⚠[/bold red]" if bk else "[green]Not detected ✓[/green]")
        console.print(Panel(t,
            title="[bold cyan]  RDP — Port 3389  [/bold cyan]",
            border_style="cyan", padding=(0,0)))
        console.print()


# ─── Deep Scan Engine ─────────────────────────────────────────────────────────

def run_nmap(ip, args, timeout=120):
    """Run nmap with given args against ip, return stdout."""
    try:
        cmd = ["nmap"] + args + [ip]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return result.stdout
    except subprocess.TimeoutExpired:
        return "[TIMEOUT]"
    except FileNotFoundError:
        return "[NMAP_NOT_FOUND]"
    except Exception as e:
        return f"[ERROR: {e}]"

def parse_nmap_ports(nmap_out):
    """Parse open ports and services from nmap output."""
    ports = []
    for line in nmap_out.splitlines():
        m = re.match(
            r'^\s*(\d+)/(tcp|udp)\s+(\S+)\s+(\S+)\s*(.*)?$', line
        )
        if m:
            ports.append({
                "port":    m.group(1),
                "proto":   m.group(2),
                "state":   m.group(3),
                "service": m.group(4),
                "version": m.group(5).strip() if m.group(5) else "",
            })
    return ports

def parse_nmap_os(nmap_out):
    """Extract OS guesses from nmap output."""
    results = []
    for line in nmap_out.splitlines():
        if "OS details:" in line:
            results.append(line.split("OS details:")[-1].strip())
        elif "Aggressive OS guesses:" in line:
            results.append(line.split("Aggressive OS guesses:")[-1].strip())
        elif "Running:" in line:
            results.append("Running: " + line.split("Running:")[-1].strip())
    return results[:3]

def parse_nmap_scripts(nmap_out):
    """Extract script output blocks from nmap."""
    scripts = {}
    current_port = None
    current_script = None
    lines = nmap_out.splitlines()
    for line in lines:
        port_m = re.match(r'^\s*(\d+/(?:tcp|udp))', line)
        if port_m:
            current_port = port_m.group(1)
        script_m = re.match(r'^\s*\|[_\s]*([\w\-]+):', line)
        if script_m and current_port:
            current_script = f"{current_port} → {script_m.group(1)}"
            val = line.split(":", 1)[-1].strip()
            if val:
                scripts[current_script] = val
        elif current_script and re.match(r'^\s*\|', line):
            extra = line.lstrip("|_ ").strip()
            if extra:
                scripts[current_script] = scripts.get(current_script, "") + "  " + extra
    return scripts

def parse_traceroute(nmap_out):
    """Extract traceroute hops."""
    hops = []
    in_trace = False
    for line in nmap_out.splitlines():
        if "TRACEROUTE" in line:
            in_trace = True
            continue
        if in_trace:
            if line.strip() == "" or line.startswith("Nmap"):
                break
            m = re.match(r'\s*(\d+)\s+(.+)', line)
            if m:
                hops.append(f"Hop {m.group(1)}: {m.group(2).strip()}")
    return hops

def deep_scan(ip):
    """
    Full power deep scan of a single host.
    Stages:
      1. Quick port sweep (all 65535 ports, SYN scan)
      2. Version + script detection on open ports
      3. OS fingerprinting
      4. Traceroute
      5. Vuln script scan on open ports
    """
    console.print()
    console.print(Panel(
        f"[bold cyan]Deep Scan[/bold cyan]  →  [yellow]{ip}[/yellow]\n"
        f"[dim]Full nmap reconnaissance: ports · services · OS · scripts · vulns · service modules[/dim]",
        border_style="cyan", padding=(0, 2)
    ))
    console.print()

    start_time = time.time()
    results = {}

    # ── Stage 1: Fast full port sweep ────────────────────────────────────────
    console.print("  [cyan]Stage 1/5[/cyan]  Fast port sweep  [dim](all 65535 ports)[/dim]")
    with Progress(SpinnerColumn(style="cyan"),
                  TextColumn("[dim]{task.description}[/dim]"),
                  TimeElapsedColumn(), console=console, transient=True) as p:
        t = p.add_task("Scanning all ports...")
        out1 = run_nmap(ip, ["-sS", "-p-", "--min-rate=3000", "-T4", "--open", "-n"], timeout=180)
        p.advance(t)

    if "[NMAP_NOT_FOUND]" in out1:
        console.print("  [red]nmap not found. Install with: [bold]sudo apt install nmap[/bold][/red]")
        return
    if "[TIMEOUT]" in out1:
        console.print("  [yellow]  Stage 1 timed out — continuing with partial results.[/yellow]")

    open_ports = parse_nmap_ports(out1)
    results["ports_raw"] = out1
    results["open_ports"] = open_ports

    port_list = ",".join(p["port"] for p in open_ports) if open_ports else "21,22,23,25,53,80,110,443,445,3306,3389,8080"
    console.print(f"  [green]✓[/green]  Found [bold]{len(open_ports)}[/bold] open port(s): [cyan]{port_list if len(port_list)<80 else port_list[:77]+'…'}[/cyan]")
    console.print()

    # ── Stage 2: Version + default scripts ───────────────────────────────────
    console.print("  [cyan]Stage 2/5[/cyan]  Service versions + default scripts")
    with Progress(SpinnerColumn(style="cyan"),
                  TextColumn("[dim]{task.description}[/dim]"),
                  TimeElapsedColumn(), console=console, transient=True) as p:
        t = p.add_task("Detecting versions & running scripts...")
        out2 = run_nmap(ip, ["-sV", "-sC", f"-p{port_list}", "-T4", "--version-intensity=7"], timeout=120)
        p.advance(t)

    results["version_out"] = out2
    results["scripts"] = parse_nmap_scripts(out2)
    ports_with_versions = parse_nmap_ports(out2)
    # merge version info back
    version_map = {p["port"]: p for p in ports_with_versions}
    for p in results["open_ports"]:
        if p["port"] in version_map:
            p["version"] = version_map[p["port"]]["version"]
            p["service"] = version_map[p["port"]]["service"]
    console.print(f"  [green]✓[/green]  Service detection complete")
    console.print()

    # ── Stage 3: OS fingerprint + traceroute ─────────────────────────────────
    console.print("  [cyan]Stage 3/5[/cyan]  OS fingerprinting + traceroute")
    with Progress(SpinnerColumn(style="cyan"),
                  TextColumn("[dim]{task.description}[/dim]"),
                  TimeElapsedColumn(), console=console, transient=True) as p:
        t = p.add_task("Fingerprinting OS...")
        out3 = run_nmap(ip, ["-O", "--traceroute", f"-p{port_list}", "-T4"], timeout=90)
        p.advance(t)

    results["os_guesses"]  = parse_nmap_os(out3)
    results["traceroute"]  = parse_traceroute(out3)
    console.print(f"  [green]✓[/green]  OS fingerprint complete")
    console.print()

    # ── Stage 4: Vuln scripts ─────────────────────────────────────────────────
    console.print("  [cyan]Stage 4/5[/cyan]  Vulnerability script scan  [dim](nmap vuln scripts)[/dim]")
    with Progress(SpinnerColumn(style="cyan"),
                  TextColumn("[dim]{task.description}[/dim]"),
                  TimeElapsedColumn(), console=console, transient=True) as p:
        t = p.add_task("Running vuln scripts...")
        out4 = run_nmap(ip, ["--script=vuln", f"-p{port_list}", "-T4"], timeout=180)
        p.advance(t)

    results["vuln_scripts"] = parse_nmap_scripts(out4)
    vuln_findings = {k: v for k, v in results["vuln_scripts"].items()
                     if any(x in v.lower() for x in ["vulnerable", "cve-", "exploit", "risk", "state: vulnerable"])}
    results["vuln_findings"] = vuln_findings
    console.print(f"  [green]✓[/green]  Vuln scan complete — [{'bold red' if vuln_findings else 'bold green'}]{len(vuln_findings)}[/{'bold red' if vuln_findings else 'bold green'}] potential finding(s)")
    console.print()

    # ── Stage 5: Port-triggered modules ──────────────────────────────────────
    open_port_list = results.get("open_ports", [])
    triggered = []
    if any(p["port"] in ("80","443","8080","8443","8000","8888","5000","3000") for p in open_port_list):
        triggered.append("HTTP")
    if any(p["port"] in ("22","2222") for p in open_port_list):
        triggered.append("SSH")
    if any(p["port"] in ("21","2121") for p in open_port_list):
        triggered.append("FTP")
    if any(p["port"] in ("445","139") for p in open_port_list):
        triggered.append("SMB")
    if any(p["port"] in ("23","2323") for p in open_port_list):
        triggered.append("Telnet")
    if any(p["port"] in ("3306","5432","1433","27017") for p in open_port_list):
        triggered.append("DB")
    if any(p["port"] == "161" for p in open_port_list):
        triggered.append("SNMP")
    if any(p["port"] == "3389" for p in open_port_list):
        triggered.append("RDP")

    if triggered:
        console.print(f"  [cyan]Stage 5/5[/cyan]  Port-triggered modules  [dim]({', '.join(triggered)})[/dim]")
        console.print()
        all_module_results = {}
        with Progress(SpinnerColumn(style="cyan"),
                      TextColumn("[dim]{task.description}[/dim]"),
                      TimeElapsedColumn(), console=console, transient=True) as p2:
            t2 = p2.add_task("Running service modules...")
            if "HTTP" in triggered:
                all_module_results["http"] = http_module(ip, open_port_list)
            if "SSH" in triggered:
                all_module_results["ssh"] = ssh_module(ip, open_port_list)
            if "FTP" in triggered:
                all_module_results["ftp"] = ftp_module(ip, open_port_list)
            if "SMB" in triggered:
                all_module_results["smb"] = smb_module(ip, open_port_list)
            if "Telnet" in triggered:
                all_module_results["telnet"] = telnet_module(ip, open_port_list)
            if "DB" in triggered:
                all_module_results["db"] = mysql_module(ip, open_port_list)
            if "SNMP" in triggered:
                all_module_results["snmp"] = snmp_module(ip, open_port_list)
            if "RDP" in triggered:
                all_module_results["rdp"] = rdp_module(ip, open_port_list)
            p2.advance(t2)
        results["modules"] = all_module_results
        console.print(f"  [green]✓[/green]  Service modules complete\n")
    else:
        results["modules"] = {}

    elapsed = time.time() - start_time
    print_deep_scan_report(ip, results, elapsed)


def print_deep_scan_report(ip, results, elapsed):
    """Render the full deep scan report in TUI style."""

    # ── Header ────────────────────────────────────────────────────────────────
    host = next((h for h in session["discovered_hosts"] if h["ip"] == ip), {})
    scanned_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    summary = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    summary.add_column("k", style="bold cyan",  width=18)
    summary.add_column("v", style="white",      width=52)
    summary.add_row("IP Address",  f"[bold white]{ip}[/bold white]")
    summary.add_row("Hostname",    f"[green]{host.get('hostname','—')}[/green]")
    summary.add_row("MAC",         host.get("mac", "—"))
    summary.add_row("Vendor",      f"[yellow]{host.get('vendor','—')}[/yellow]")
    summary.add_row("Device Type", host.get("device_type","—"))
    summary.add_row("Scanned At",  scanned_at)
    summary.add_row("Scan Time",   f"{elapsed:.1f}s")

    console.print(Panel(summary,
        title=f"[bold cyan]  Deep Scan Report — {ip}  [/bold cyan]",
        border_style="cyan", padding=(0, 0)))
    console.print()

    # ── OS Guesses ───────────────────────────────────────────────────────────
    os_guesses = results.get("os_guesses", [])
    if os_guesses:
        console.print(Panel(
            "\n".join(f"  [yellow]{g}[/yellow]" for g in os_guesses),
            title="[bold cyan]  OS Fingerprint  [/bold cyan]",
            border_style="cyan", padding=(0, 0)
        ))
        console.print()

    # ── Open Ports & Services ─────────────────────────────────────────────────
    open_ports = results.get("open_ports", [])
    if open_ports:
        ptable = Table(
            title="[bold cyan]Open Ports & Services[/bold cyan]",
            box=box.ROUNDED, border_style="cyan",
            header_style="bold cyan", padding=(0, 1), show_lines=False
        )
        ptable.add_column("Port",    style="bold white",  width=8)
        ptable.add_column("Proto",   style="dim cyan",    width=6)
        ptable.add_column("State",   style="bold green",  width=8)
        ptable.add_column("Service", style="yellow",      width=14)
        ptable.add_column("Version / Banner",             width=55)

        svc_colors = {
            "http": "blue", "https": "blue", "ssh": "magenta",
            "ftp": "red", "smb": "red", "rdp": "red",
            "mysql": "yellow", "mssql": "yellow",
            "telnet": "red", "smtp": "cyan",
        }
        for p in open_ports:
            svc = p["service"].lower()
            color = svc_colors.get(svc, "white")
            state_str = f"[bold green]{p['state']}[/bold green]" if p["state"] == "open" else f"[yellow]{p['state']}[/yellow]"
            ptable.add_row(
                p["port"], p["proto"], state_str,
                f"[{color}]{p['service']}[/{color}]",
                f"[dim]{p['version'][:80]}[/dim]" if p["version"] else "[dim]—[/dim]"
            )
        console.print(ptable)
        console.print()
    else:
        console.print("  [yellow]No open ports found.[/yellow]\n")

    # ── Script Results ────────────────────────────────────────────────────────
    scripts = results.get("scripts", {})
    if scripts:
        stable = Table(
            title="[bold cyan]Script Results[/bold cyan]",
            box=box.ROUNDED, border_style="cyan",
            header_style="bold cyan", padding=(0, 1), show_lines=True
        )
        stable.add_column("Port → Script", style="cyan",  width=35)
        stable.add_column("Output",        style="white", width=55)
        for key, val in list(scripts.items())[:25]:
            stable.add_row(key, val[:200])
        console.print(stable)
        console.print()

    # ── Traceroute ────────────────────────────────────────────────────────────
    hops = results.get("traceroute", [])
    if hops:
        console.print(Panel(
            "\n".join(f"  [dim]{h}[/dim]" for h in hops),
            title="[bold cyan]  Traceroute  [/bold cyan]",
            border_style="cyan", padding=(0, 0)
        ))
        console.print()

    # ── Vuln Findings ─────────────────────────────────────────────────────────
    vulns = results.get("vuln_findings", {})
    if vulns:
        vtable = Table(
            title="[bold red]⚠  Vulnerability Findings[/bold red]",
            box=box.ROUNDED, border_style="red",
            header_style="bold red", padding=(0, 1), show_lines=True
        )
        vtable.add_column("Port → Script", style="red",   width=35)
        vtable.add_column("Finding",       style="white", width=55)
        for key, val in vulns.items():
            vtable.add_row(key, val[:200])
        console.print(vtable)
        console.print()
    else:
        console.print("  [green]✓  No known vulnerabilities detected by nmap vuln scripts.[/green]")
        console.print()

    # ── Port-Triggered Module Results ─────────────────────────────────────────
    module_res = results.get("modules", {})
    if module_res:
        console.print(Panel(
            "[bold cyan]Port-Triggered Service Analysis[/bold cyan]  [dim]— auto-run based on open ports[/dim]",
            border_style="cyan", padding=(0,2)
        ))
        console.print()
        print_module_results(module_res)

    console.print(f"  [dim]Scan completed in {elapsed:.1f}s  |  {scanned_at}[/dim]\n")


def print_host_detail(ip):
    """Entry point for `info <ip>` — runs full deep scan."""
    # Validate IP
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        console.print(f"  [red]Invalid IP address: [bold]{ip}[/bold][/red]")
        return

    # If not in discovered hosts, still allow scanning (user may type any IP)
    if not any(h["ip"] == ip for h in session["discovered_hosts"]):
        console.print(f"  [yellow]Note: {ip} was not found in the last scan. Scanning anyway...[/yellow]")
        # Quick enrich so report has something
        iface = session.get("interface")
        host = enrich_host(ip)
        session["discovered_hosts"].append(host)

    deep_scan(ip)

# ─── Scan Flow ────────────────────────────────────────────────────────────────

def run_scan():
    if not session["target_range"]:
        console.print("[red]  No target set. Use [bold]set target <CIDR>[/bold] first.[/red]")
        return

    target = session["target_range"]
    console.print()
    console.print(Panel(
        f"[bold cyan]ICMP Ping Sweep[/bold cyan]  →  [yellow]{target}[/yellow]\n"
        f"[dim]Sending ICMP echo requests to all hosts in range...[/dim]",
        border_style="cyan",
        padding=(0, 2)
    ))
    console.print()

    try:
        network = ipaddress.ip_network(target, strict=False)
        total = network.num_addresses - 2
        if total <= 0:
            total = 1
    except Exception:
        total = 255

    completed = [0]

    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold cyan]Scanning[/bold cyan]"),
        BarColumn(bar_width=40, complete_style="cyan", finished_style="green"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TextColumn("[dim]|[/dim] [green]{task.fields[found]}[/green] [dim]alive[/dim]"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("scan", total=total, found=0)

        alive_ref = []
        lock = threading.Lock()

        def cb():
            completed[0] += 1
            progress.update(task, completed=completed[0], found=len(alive_ref))

        # run sweep in a thread so progress renders
        def sweep_thread():
            hosts = icmp_sweep(target, progress_callback=cb)
            with lock:
                alive_ref.extend(hosts)

        t = threading.Thread(target=sweep_thread)
        t.start()
        t.join()

    alive = alive_ref
    session["scan_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if not alive:
        console.print("[yellow]  No live hosts found.[/yellow]")
        return

    console.print(f"  [bold green]✓[/bold green]  Found [bold green]{len(alive)}[/bold green] live hosts. Enriching (hostname, MAC, vendor)...\n")

    enriched = []
    with Progress(
        SpinnerColumn(style="cyan"),
        TextColumn("[bold cyan]Enriching hosts[/bold cyan]"),
        BarColumn(bar_width=40, complete_style="cyan", finished_style="green"),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
        transient=True,
    ) as progress:
        task = progress.add_task("enrich", total=len(alive))
        with ThreadPoolExecutor(max_workers=20) as ex:
            futures = {ex.submit(enrich_host, ip): ip for ip in alive}
            for f in as_completed(futures):
                enriched.append(f.result())
                progress.advance(task)

    session["discovered_hosts"] = sorted(enriched, key=lambda x: [int(o) for o in x["ip"].split(".")])
    print_hosts(session["discovered_hosts"], title="Scan Results")

# ─── Command Parser ───────────────────────────────────────────────────────────

def handle_command(raw):
    parts = raw.strip().split()
    if not parts:
        return

    cmd = parts[0].lower()

    if cmd in ("exit", "quit"):
        console.print("\n[dim]  Goodbye.[/dim]\n")
        sys.exit(0)

    elif cmd == "help":
        print_help()

    elif cmd == "clear":
        print_banner()
        print_status_bar()

    elif cmd == "scan":
        run_scan()

    elif cmd == "hosts":
        if len(parts) >= 3 and parts[1].lower() == "filter":
            kw = " ".join(parts[2:])
            print_hosts(session["discovered_hosts"], filter_kw=kw)
        else:
            print_hosts(session["discovered_hosts"])

    elif cmd == "info" and len(parts) >= 2:
        print_host_detail(parts[1])

    elif cmd == "set" and len(parts) >= 3 and parts[1].lower() == "target":
        value = parts[2].lower()
        if value == "auto":
            local_ip, _ = get_local_ip_and_iface()
            subnet = get_subnet_from_ip(local_ip)
            session["target_range"] = subnet
            console.print(f"  [bold green]✓[/bold green]  Target auto-set to [bold yellow]{subnet}[/bold yellow]")
        else:
            try:
                ipaddress.ip_network(parts[2], strict=False)
                session["target_range"] = parts[2]
                console.print(f"  [bold green]✓[/bold green]  Target set to [bold yellow]{parts[2]}[/bold yellow]")
            except ValueError:
                console.print(f"  [red]Invalid CIDR: [bold]{parts[2]}[/bold][/red]")

    else:
        console.print(f"  [red]Unknown command: [bold]{raw.strip()}[/bold][/red]  (type [bold cyan]help[/bold cyan])")

# ─── Main Loop ────────────────────────────────────────────────────────────────

def main():
    if os.geteuid() != 0:
        console.print()
        console.print(Panel(
            "[bold red]NetRecon requires root privileges.[/bold red]\n"
            "[dim]Please run with: [bold]sudo python3 netrecon.py[/bold][/dim]",
            border_style="red"
        ))
        sys.exit(1)

    print_banner()
    print_status_bar()
    console.print("  [dim]Type [bold cyan]help[/bold cyan] to see all commands. Type [bold cyan]set target auto[/bold cyan] to start.[/dim]\n")

    while True:
        try:
            raw = Prompt.ask("[bold cyan]netrecon[/bold cyan][white]>[/white]")
        except (KeyboardInterrupt, EOFError):
            console.print("\n[dim]  Use [bold]exit[/bold] to quit.[/dim]")
            continue
        handle_command(raw)

if __name__ == "__main__":
    main()

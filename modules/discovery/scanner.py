"""
NetWatch — Network Discovery Module
Discovers all devices on your network using ARP scanning and Nmap.
Performs OS fingerprinting, port scanning, and MAC vendor lookup.

DISCLAIMER: Use only on networks you own or are authorized to scan.
"""
import logging
import subprocess
import socket
import ipaddress
import json
import re
import time
from datetime import datetime
from typing import List, Dict, Optional
import threading

log = logging.getLogger("netwatch.discovery")


# OUI → Vendor database (top vendors; full lookup via nmap or API)
_OUI_CACHE: Dict[str, str] = {}


def _mac_prefix(mac: str) -> str:
    """Return normalized OUI prefix from MAC address."""
    return mac.upper().replace("-", ":").replace(".", ":")[:8]


def lookup_vendor(mac: str) -> str:
    """Look up vendor name from MAC OUI using nmap's mac-prefixes database."""
    prefix = _mac_prefix(mac)
    if prefix in _OUI_CACHE:
        return _OUI_CACHE[prefix]

    # Try reading nmap's mac-prefixes file
    for path in ["/usr/share/nmap/nmap-mac-prefixes",
                 "/opt/homebrew/share/nmap/nmap-mac-prefixes"]:
        try:
            with open(path, "r") as f:
                for line in f:
                    parts = line.strip().split(" ", 1)
                    if len(parts) == 2:
                        p = parts[0]
                        formatted = f"{p[0:2]}:{p[2:4]}:{p[4:6]}"
                        _OUI_CACHE[formatted] = parts[1]
            vendor = _OUI_CACHE.get(prefix, "Unknown")
            return vendor
        except FileNotFoundError:
            continue

    return "Unknown"


def arp_scan(subnet: str, interface: str) -> List[Dict]:
    """
    Perform ARP scan to discover live hosts.
    Returns list of {ip, mac} dicts.

    Uses arp-scan if available, falls back to nmap ARP ping.
    """
    devices = []

    # Try arp-scan first (fastest and most reliable)
    try:
        result = subprocess.run(
            ["arp-scan", "--interface", interface, "--localnet",
             "--retry=3", "--ignoredups"],
            capture_output=True, text=True, timeout=30
        )
        for line in result.stdout.splitlines():
            # arp-scan output: "192.168.1.5\t00:11:22:33:44:55\tVendor Name"
            parts = line.strip().split("\t")
            if len(parts) >= 2:
                ip  = parts[0].strip()
                mac = parts[1].strip().upper()
                if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip) and len(mac) == 17:
                    devices.append({"ip": ip, "mac": mac})
        if devices:
            log.debug("arp-scan found %d devices", len(devices))
            return devices
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        log.debug("arp-scan not available or timed out: %s", e)

    # Fallback: nmap ARP ping (-sn -PR)
    try:
        result = subprocess.run(
            ["nmap", "-sn", "-PR", "--send-eth", subnet],
            capture_output=True, text=True, timeout=60
        )
        current_ip = None
        for line in result.stdout.splitlines():
            ip_match  = re.search(r"Nmap scan report for (\S+)", line)
            mac_match = re.search(r"MAC Address: ([0-9A-F:]{17})", line)
            if ip_match:
                # Extract IP from hostname (ip) or just ip
                addr = ip_match.group(1)
                ip_extract = re.search(r"\((\d+\.\d+\.\d+\.\d+)\)", addr)
                current_ip = ip_extract.group(1) if ip_extract else addr
            if mac_match and current_ip:
                devices.append({"ip": current_ip, "mac": mac_match.group(1).upper()})
                current_ip = None
        log.debug("nmap ARP ping found %d devices", len(devices))
    except Exception as e:
        log.error("nmap ARP ping failed: %s", e)

    return devices


def nmap_scan_device(ip: str, do_os: bool = True, ports: str = "21,22,23,25,53,80,443,445,3389,8080,8443") -> Dict:
    """
    Full Nmap scan of a single device.
    Returns: {hostname, os_guess, open_ports: [{port, service, state}]}

    Requires root/sudo for OS detection (-O flag).
    """
    result = {"hostname": None, "os_guess": None, "open_ports": []}

    # Build nmap command
    cmd = ["nmap", "-sV", "--version-intensity", "3", "-T4", "-p", ports]
    if do_os:
        cmd += ["-O", "--osscan-guess"]
    cmd.append(ip)

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        output = proc.stdout

        # Extract hostname
        h = re.search(r"Nmap scan report for (\S+)", output)
        if h:
            addr_part = h.group(1)
            if "(" not in addr_part:
                # Could be hostname or IP
                if not re.match(r"^\d+\.\d+\.\d+\.\d+$", addr_part):
                    result["hostname"] = addr_part
            else:
                result["hostname"] = addr_part.split("(")[0].strip()

        # Try reverse DNS as fallback
        if not result["hostname"]:
            try:
                result["hostname"] = socket.gethostbyaddr(ip)[0]
            except Exception:
                pass

        # Extract open ports
        for line in output.splitlines():
            # Format: "80/tcp   open  http   Apache httpd 2.4.41"
            m = re.match(r"(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)\s*(.*)", line)
            if m and m.group(3) == "open":
                result["open_ports"].append({
                    "port":    int(m.group(1)),
                    "proto":   m.group(2),
                    "service": m.group(4),
                    "version": m.group(5).strip(),
                })

        # Extract OS guess
        os_m = re.search(r"OS details?: (.+)", output)
        if os_m:
            result["os_guess"] = os_m.group(1).strip()
        else:
            ag_m = re.search(r"Aggressive OS guesses?: (.+?)(?:\n|$)", output)
            if ag_m:
                result["os_guess"] = ag_m.group(1).split(",")[0].strip()

    except subprocess.TimeoutExpired:
        log.warning("Nmap scan timed out for %s", ip)
    except Exception as e:
        log.error("Nmap scan error for %s: %s", ip, e)

    return result


class NetworkScanner:
    """
    Main network discovery engine.
    Runs ARP scan + detailed Nmap scan on all discovered devices.
    Emits events on discovery/update.
    """

    def __init__(self, config: dict, db, event_bus):
        self.config    = config
        self.db        = db
        self.bus       = event_bus
        self.interface = config["network"]["interface"]
        self.subnet    = config["network"]["subnet"]
        self.disc_cfg  = config.get("discovery", {})
        self._running  = False
        self._lock     = threading.Lock()

    def scan_once(self) -> List[Dict]:
        """Run a single full network scan and update the database."""
        log.info("Starting ARP scan on %s (%s)...", self.subnet, self.interface)
        start = time.time()

        arp_results = arp_scan(self.subnet, self.interface)
        if not arp_results:
            log.warning("ARP scan returned 0 devices. Check interface and subnet.")
            return []

        active_macs = []
        results     = []

        # Run detailed scans concurrently (thread pool)
        def _scan_device(entry: Dict):
            ip  = entry["ip"]
            mac = entry["mac"]
            active_macs.append(mac)

            detail = {}
            if self.disc_cfg.get("port_scan", True) or self.disc_cfg.get("os_fingerprint", True):
                detail = nmap_scan_device(
                    ip,
                    do_os=self.disc_cfg.get("os_fingerprint", True),
                    ports=self.disc_cfg.get("ports", "21,22,80,443,445,3389")
                )

            vendor = lookup_vendor(mac)

            is_new = self.db.session().query(
                __import__("sqlalchemy").exists().where(
                    __import__("netwatch.core.database", fromlist=["Device"]).Device.mac == mac
                )
            ).scalar()

            dev = self.db.upsert_device(
                mac=mac,
                ip=ip,
                hostname=detail.get("hostname"),
                vendor=vendor,
                os_guess=detail.get("os_guess"),
                open_ports=detail.get("open_ports", []),
                is_active=True,
            )
            results.append(dev.to_dict())

            # Fire appropriate event
            if not is_new:
                self.bus.publish("device.discovered", dev.to_dict())
                log.info("New device: %s (%s) [%s] - %s", ip, mac, vendor, detail.get("os_guess", "?"))
            else:
                self.bus.publish("device.updated", dev.to_dict())

        threads = []
        for entry in arp_results:
            t = threading.Thread(target=_scan_device, args=(entry,), daemon=True)
            threads.append(t)
            t.start()
        for t in threads:
            t.join(timeout=130)

        # Mark absent devices inactive
        self.db.mark_devices_inactive(active_macs)

        elapsed = time.time() - start
        log.info("Scan complete: %d devices in %.1fs", len(results), elapsed)
        self.bus.publish("scan.complete", {"device_count": len(results), "elapsed": elapsed})

        return results

    def start_continuous(self):
        """Start background scanning loop."""
        self._running = True
        interval = self.disc_cfg.get("interval", 60)

        def _loop():
            while self._running:
                try:
                    self.scan_once()
                except Exception as e:
                    log.error("Scan loop error: %s", e)
                time.sleep(interval)

        t = threading.Thread(target=_loop, daemon=True, name="scanner")
        t.start()
        log.info("Continuous scanning started (interval=%ds)", interval)

    def stop(self):
        self._running = False

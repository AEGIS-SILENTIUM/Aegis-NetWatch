"""
NetWatch — Traffic Monitor
Captures and analyzes network traffic on your own network.
Uses tshark (Wireshark CLI) for packet capture and analysis.

DISCLAIMER: Use only on networks you own or are authorized to monitor.
"""
import logging
import subprocess
import json
import threading
import time
import os
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Optional

log = logging.getLogger("netwatch.traffic")

# Port → service name mapping
PORT_SERVICES = {
    20: "FTP-data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 80: "HTTP", 110: "POP3", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "SMTP-TLS",
    993: "IMAPS", 995: "POP3S", 1194: "OpenVPN", 1433: "MSSQL",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

def _guess_service(dst_port: Optional[int]) -> Optional[str]:
    if dst_port is None:
        return None
    return PORT_SERVICES.get(dst_port)


class BandwidthTracker:
    """Per-IP byte counters with sliding window for Mbps calculation."""

    def __init__(self):
        self._counts: Dict[str, Dict] = defaultdict(lambda: {"in": 0, "out": 0, "ts": time.time()})
        self._lock = threading.Lock()

    def record(self, src_ip: str, dst_ip: str, length: int):
        with self._lock:
            self._counts[src_ip]["out"] += length
            self._counts[dst_ip]["in"]  += length

    def get_and_reset(self) -> Dict[str, Dict]:
        with self._lock:
            snap = dict(self._counts)
            self._counts.clear()
            return snap


class TrafficMonitor:
    """
    Captures live traffic using tshark and stores flows in the database.
    Also tracks per-device bandwidth for alerting.
    """

    def __init__(self, config: dict, db, event_bus):
        self.config    = config
        self.db        = db
        self.bus       = event_bus
        self.interface = config["network"]["interface"]
        self.tc        = config.get("traffic", {})
        self._running  = False
        self.bw        = BandwidthTracker()
        self._proc: Optional[subprocess.Popen] = None

    def _build_tshark_cmd(self) -> List[str]:
        """Build the tshark command for packet capture."""
        cmd = [
            "tshark",
            "-i", self.interface,
            "-T", "json",
            "-e", "ip.src",
            "-e", "ip.dst",
            "-e", "tcp.srcport",
            "-e", "tcp.dstport",
            "-e", "udp.srcport",
            "-e", "udp.dstport",
            "-e", "frame.len",
            "-e", "ip.proto",
            "-e", "_ws.col.Protocol",
            "-E", "header=n",
            "-l",  # Line-buffered output
        ]
        capture_filter = self.tc.get("filter", "")
        if capture_filter:
            cmd += ["-f", capture_filter]
        return cmd

    def _parse_tshark_packet(self, pkt: dict) -> Optional[dict]:
        """Parse a single tshark JSON packet into a flow dict."""
        try:
            layers = pkt.get("_source", {}).get("layers", {})
            src_ip = (layers.get("ip.src", [None]) or [None])[0]
            dst_ip = (layers.get("ip.dst", [None]) or [None])[0]
            if not src_ip or not dst_ip:
                return None

            length   = int((layers.get("frame.len", ["0"]) or ["0"])[0] or 0)
            protocol = (layers.get("_ws.col.Protocol", [None]) or [None])[0]

            src_port = dst_port = None
            if "tcp.srcport" in layers:
                src_port = int((layers["tcp.srcport"][0] or 0))
                dst_port = int((layers.get("tcp.dstport", ["0"])[0] or 0))
            elif "udp.srcport" in layers:
                src_port = int((layers["udp.srcport"][0] or 0))
                dst_port = int((layers.get("udp.dstport", ["0"])[0] or 0))

            return {
                "src_ip": src_ip, "dst_ip": dst_ip,
                "src_port": src_port, "dst_port": dst_port,
                "protocol": protocol, "bytes_sent": length,
                "service": _guess_service(dst_port),
            }
        except Exception as e:
            log.debug("Packet parse error: %s", e)
            return None

    def _capture_loop(self):
        """Main capture loop — reads tshark JSON output line by line."""
        cmd = self._build_tshark_cmd()
        log.info("Starting capture: %s", " ".join(cmd))

        buffer = ""
        depth  = 0

        try:
            self._proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
            )

            for line in self._proc.stdout:
                if not self._running:
                    break
                line = line.strip()

                # tshark -T json emits one large JSON array; we parse objects one by one
                for char in line:
                    buffer += char
                    if char == "{":
                        depth += 1
                    elif char == "}":
                        depth -= 1
                        if depth == 0 and buffer.strip():
                            # Try to parse complete object
                            clean = buffer.strip().rstrip(",")
                            try:
                                pkt = json.loads(clean)
                                flow = self._parse_tshark_packet(pkt)
                                if flow:
                                    self._handle_flow(flow)
                            except json.JSONDecodeError:
                                pass
                            buffer = ""

        except FileNotFoundError:
            log.error("tshark not found. Install with: sudo apt-get install tshark")
        except Exception as e:
            log.error("Capture loop error: %s", e)
        finally:
            if self._proc:
                self._proc.terminate()

    def _handle_flow(self, flow: dict):
        """Store flow to database and update bandwidth tracker."""
        try:
            self.db.add_flow(**flow)
            self.bw.record(flow["src_ip"], flow["dst_ip"], flow.get("bytes_sent", 0))
            self.bus.publish("flow.captured", flow)
        except Exception as e:
            log.debug("Flow handling error: %s", e)

    def _bandwidth_reporter(self):
        """Every 10s, snapshot bandwidth counters and store samples."""
        while self._running:
            time.sleep(10)
            try:
                snap = self.bw.get_and_reset()
                for ip, counts in snap.items():
                    if counts["in"] + counts["out"] > 0:
                        # Get MAC for this IP
                        dev = None
                        devs = self.db.get_active_devices()
                        for d in devs:
                            if d.ip == ip:
                                dev = d
                                break
                        self.db.add_bandwidth_sample(
                            device_ip=ip,
                            device_mac=dev.mac if dev else None,
                            bytes_in=counts["in"],
                            bytes_out=counts["out"],
                        )
                        self.bus.publish("bandwidth.sample", {
                            "ip": ip, "bytes_in": counts["in"],
                            "bytes_out": counts["out"],
                        })
            except Exception as e:
                log.debug("Bandwidth reporter error: %s", e)

    def start(self):
        """Start packet capture and bandwidth reporting in background."""
        if not self.tc.get("enabled", True):
            log.info("Traffic monitoring disabled in config")
            return

        self._running = True
        threading.Thread(target=self._capture_loop,      daemon=True, name="capture").start()
        threading.Thread(target=self._bandwidth_reporter, daemon=True, name="bw_report").start()
        log.info("Traffic monitor started on interface %s", self.interface)

    def stop(self):
        self._running = False
        if self._proc:
            self._proc.terminate()

    def get_top_talkers(self, limit: int = 10) -> List[Dict]:
        """Return top N devices by recent traffic volume."""
        flows = self.db.get_recent_flows(minutes=5, limit=5000)
        counts: Dict[str, int] = defaultdict(int)
        for f in flows:
            counts[f.src_ip] += f.bytes_sent
        sorted_items = sorted(counts.items(), key=lambda x: x[1], reverse=True)
        return [{"ip": ip, "bytes": b} for ip, b in sorted_items[:limit]]

    def get_protocol_breakdown(self, minutes: int = 5) -> Dict[str, int]:
        """Return byte count by protocol for recent traffic."""
        flows = self.db.get_recent_flows(minutes=minutes, limit=5000)
        breakdown: Dict[str, int] = defaultdict(int)
        for f in flows:
            proto = f.protocol or "Other"
            breakdown[proto] += f.bytes_sent
        return dict(breakdown)

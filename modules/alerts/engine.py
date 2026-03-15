"""
NetWatch — Alert Engine
Rule-based alert system. Fires alerts for:
  - New device discovered on your network
  - Port scan behavior detected
  - Bandwidth spike from a device
  - Suspicious DNS query
  - Telnet/insecure protocol detected
Sends alerts to the database, dashboard (via WebSocket), and optional webhook/email.

DISCLAIMER: Use only on networks you own or are authorized to monitor.
"""
import logging
import threading
import time
import json
import smtplib
from email.mime.text import MIMEText
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, Set
try:
    import requests as _requests
except ImportError:
    _requests = None

log = logging.getLogger("netwatch.alerts")


class AlertEngine:
    """Processes events from the event bus and fires alerts."""

    def __init__(self, config: dict, db, event_bus):
        self.config   = config
        self.db       = db
        self.bus      = event_bus
        self.ac       = config.get("alerts", {})
        self._enabled = self.ac.get("enabled", True)

        # State for stateful detections
        self._known_macs:      Set[str] = set()
        self._port_scan_track: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self._bw_track:        Dict[str, float] = {}
        self._lock = threading.Lock()

        if self._enabled:
            self._subscribe()
            # Load known MACs from DB on startup
            threading.Thread(target=self._load_known_macs, daemon=True).start()

    def _load_known_macs(self):
        time.sleep(2)  # Wait for DB to be ready
        try:
            devs = self.db.get_all_devices()
            with self._lock:
                self._known_macs = {d.mac for d in devs}
            log.info("Loaded %d known MACs", len(self._known_macs))
        except Exception as e:
            log.error("Failed to load known MACs: %s", e)

    def _subscribe(self):
        """Subscribe to relevant events."""
        self.bus.subscribe("device.discovered", self._on_device_discovered)
        self.bus.subscribe("flow.captured",     self._on_flow)
        self.bus.subscribe("dns.query",         self._on_dns)
        self.bus.subscribe("bandwidth.sample",  self._on_bandwidth)

    # ── Alert Handlers ────────────────────────────────────────

    def _on_device_discovered(self, device: dict):
        """Alert when a new device appears on the network."""
        if not self.ac.get("new_device", True):
            return
        mac = device.get("mac", "")
        with self._lock:
            if mac in self._known_macs:
                return
            self._known_macs.add(mac)

        self._fire(
            severity="MEDIUM",
            category="new_device",
            title=f"New device on network: {device.get('ip', '?')}",
            description=(
                f"MAC: {mac}\n"
                f"Vendor: {device.get('vendor', 'Unknown')}\n"
                f"Hostname: {device.get('hostname', 'Unknown')}\n"
                f"OS: {device.get('os_guess', 'Unknown')}"
            ),
            device_mac=mac,
            device_ip=device.get("ip"),
            extra_data=device,
        )

    def _on_flow(self, flow: dict):
        """Detect port scan behavior: many distinct ports from same source."""
        if not self.ac.get("port_scan_detection", True):
            return
        src = flow.get("src_ip")
        dst_port = flow.get("dst_port")
        if not src or not dst_port:
            return

        with self._lock:
            tracker = self._port_scan_track[src]
            tracker.append((dst_port, time.time()))

            # Count distinct ports in last 10 seconds
            now = time.time()
            recent = [p for p, t in tracker if now - t < 10]
            distinct = len(set(recent))

        if distinct >= 15:
            self._fire(
                severity="HIGH",
                category="port_scan",
                title=f"Possible port scan from {src}",
                description=f"Device {src} hit {distinct} distinct ports in 10 seconds.",
                device_ip=src,
                extra_data={"distinct_ports": distinct, "sample_ports": list(set(recent))[:10]},
            )
            # Reset to avoid spam
            with self._lock:
                self._port_scan_track[src].clear()

        # Alert on Telnet (port 23) — insecure protocol
        if dst_port == 23:
            self._fire(
                severity="MEDIUM",
                category="insecure_protocol",
                title=f"Telnet connection from {src}",
                description=f"Device {src} initiated a Telnet connection (unencrypted). Consider using SSH.",
                device_ip=src,
            )

    def _on_dns(self, data: dict):
        """Alert on suspicious DNS queries."""
        if not self.ac.get("dns_anomaly", True):
            return
        if data.get("flagged"):
            self._fire(
                severity="HIGH",
                category="dns_anomaly",
                title=f"Suspicious DNS query from {data.get('src_ip', '?')}",
                description=f"Domain: {data.get('domain', '?')}\nType: {data.get('qtype', '?')}",
                device_ip=data.get("src_ip"),
                extra_data=data,
            )

    def _on_bandwidth(self, data: dict):
        """Alert when a device exceeds bandwidth threshold."""
        threshold_bps = self.ac.get("bandwidth_spike_mbps", 50) * 1_000_000 / 8
        ip   = data.get("ip")
        # bytes_in + bytes_out in 10s window
        total_bytes = data.get("bytes_in", 0) + data.get("bytes_out", 0)
        bps = total_bytes / 10  # 10-second window

        if bps > threshold_bps:
            mbps = bps * 8 / 1_000_000
            self._fire(
                severity="MEDIUM",
                category="bandwidth_spike",
                title=f"Bandwidth spike: {ip} using {mbps:.1f} Mbps",
                description=f"Device {ip} exceeded {self.ac.get('bandwidth_spike_mbps')} Mbps threshold.",
                device_ip=ip,
                extra_data={"mbps": round(mbps, 2)},
            )

    # ── Fire Alert ────────────────────────────────────────────

    def _fire(self, severity: str, category: str, title: str, **kwargs):
        """Create an alert in the database and send notifications."""
        try:
            alert = self.db.add_alert(
                severity=severity,
                category=category,
                title=title,
                **kwargs,
            )
            self.bus.publish("alert.fired", alert.to_dict())
            self._send_webhook(alert.to_dict())
            self._send_email(alert.to_dict())
        except Exception as e:
            log.error("Alert fire error: %s", e)

    # ── Notifications ─────────────────────────────────────────

    def _send_webhook(self, alert: dict):
        url = self.ac.get("webhook_url", "")
        if not url or _requests is None:
            return
        try:
            _requests.post(url, json=alert, timeout=5)
        except Exception as e:
            log.debug("Webhook error: %s", e)

    def _send_email(self, alert: dict):
        ec = self.ac.get("email", {})
        if not ec.get("enabled") or not ec.get("from") or not ec.get("to"):
            return
        try:
            msg = MIMEText(
                f"Severity: {alert['severity']}\n"
                f"Category: {alert['category']}\n\n"
                f"{alert['description']}\n\n"
                f"Time: {alert['timestamp']}"
            )
            msg["Subject"] = f"[NetWatch {alert['severity']}] {alert['title']}"
            msg["From"]    = ec["from"]
            msg["To"]      = ec["to"]

            with smtplib.SMTP(ec.get("smtp_host", "localhost"), ec.get("smtp_port", 587)) as s:
                s.starttls()
                s.login(ec["from"], ec.get("password", ""))
                s.send_message(msg)
        except Exception as e:
            log.debug("Email alert error: %s", e)

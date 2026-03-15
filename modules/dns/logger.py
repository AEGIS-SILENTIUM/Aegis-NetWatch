"""
NetWatch — DNS Logger
Captures and logs all DNS queries from all devices on your network.
Uses scapy for passive DNS sniffing on your own network interface.

DISCLAIMER: Use only on networks you own or are authorized to monitor.
"""
import logging
import threading
import time
from datetime import datetime
from typing import Set

log = logging.getLogger("netwatch.dns")

# Known malware/tracking domain patterns for flagging
_SUSPICIOUS_PATTERNS = [
    ".onion", "dga-", "malware", "botnet", "c2.", "cnc.",
    ".ru.com", "free-money", "click-here",
]

def _is_suspicious(domain: str) -> bool:
    domain_lower = domain.lower()
    return any(p in domain_lower for p in _SUSPICIOUS_PATTERNS)


class DnsLogger:
    """
    Passively sniffs DNS queries on your network interface.
    Uses scapy to capture UDP port 53 traffic.
    Logs all queries with source IP, domain, type, and response.
    """

    def __init__(self, config: dict, db, event_bus):
        self.config    = config
        self.db        = db
        self.bus       = event_bus
        self.interface = config["network"]["interface"]
        self.dc        = config.get("dns", {})
        self._running  = False
        self._seen:    Set[str] = set()  # Dedup key = "ip:domain:qtype"

    def _handle_packet(self, pkt):
        """Callback for each captured DNS packet."""
        try:
            from scapy.layers.dns import DNS, DNSQR, DNSRR
            from scapy.layers.inet import IP

            if not pkt.haslayer(DNS):
                return

            dns  = pkt[DNS]
            ip   = pkt[IP] if pkt.haslayer(IP) else None

            if not ip or dns.qr != 0:  # qr=0 means query (not response)
                return
            if not dns.qd:
                return

            src_ip = ip.src
            domain = dns.qd.qname.decode(errors="replace").rstrip(".")
            qtype  = {1: "A", 28: "AAAA", 15: "MX", 16: "TXT",
                      2: "NS", 5: "CNAME", 255: "ANY"}.get(dns.qd.qtype, str(dns.qd.qtype))

            # Deduplicate within 5 seconds
            dedup_key = f"{src_ip}:{domain}:{qtype}"
            if dedup_key in self._seen:
                return
            self._seen.add(dedup_key)

            # Extract response if this is a query+response (unlikely in passive sniff)
            response = None

            flagged = _is_suspicious(domain)

            self.db.add_dns_query(
                src_ip=src_ip,
                domain=domain,
                qtype=qtype,
                response=response,
                flagged=flagged,
            )
            self.bus.publish("dns.query", {
                "src_ip": src_ip, "domain": domain,
                "qtype": qtype, "flagged": flagged,
            })

            if flagged:
                log.warning("Suspicious DNS query from %s: %s", src_ip, domain)

        except Exception as e:
            log.debug("DNS packet error: %s", e)

    def _cleanup_dedup(self):
        """Clear dedup cache every 10 seconds to prevent memory growth."""
        while self._running:
            time.sleep(10)
            self._seen.clear()

    def start(self):
        """Start passive DNS sniffing in a background thread."""
        if not self.dc.get("enabled", True):
            log.info("DNS logging disabled in config")
            return

        def _sniff():
            try:
                from scapy.all import sniff
                log.info("DNS logger started on %s (sniffing UDP/53)", self.interface)
                sniff(
                    iface=self.interface,
                    filter="udp port 53",
                    prn=self._handle_packet,
                    store=False,
                    stop_filter=lambda _: not self._running,
                )
            except ImportError:
                log.error("scapy not installed. Install with: pip3 install scapy")
            except PermissionError:
                log.error("Permission denied for packet sniff. Run as root/sudo.")
            except Exception as e:
                log.error("DNS sniffer error: %s", e)

        self._running = True
        threading.Thread(target=_sniff,              daemon=True, name="dns_sniff").start()
        threading.Thread(target=self._cleanup_dedup, daemon=True, name="dns_dedup").start()

    def stop(self):
        self._running = False

    def get_top_domains(self, limit: int = 20) -> list:
        """Return top queried domains across all devices."""
        from collections import Counter
        queries = self.db.get_recent_dns(minutes=60, limit=5000)
        counts  = Counter(q.domain for q in queries)
        return [{"domain": d, "count": c} for d, c in counts.most_common(limit)]

    def get_top_domains_by_device(self, ip: str, limit: int = 20) -> list:
        """Return top domains queried by a specific device."""
        from collections import Counter
        queries = self.db.get_dns_by_device(ip, limit=1000)
        counts  = Counter(q.domain for q in queries)
        return [{"domain": d, "count": c} for d, c in counts.most_common(limit)]

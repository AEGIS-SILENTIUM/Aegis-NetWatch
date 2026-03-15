"""
NetWatch — Event Bus
Simple publish/subscribe system for inter-module communication.

DISCLAIMER: For authorized use on networks/devices you own only.
"""
import logging
import threading
from collections import defaultdict
from typing import Callable, Any

log = logging.getLogger("netwatch.events")


class EventBus:
    """Thread-safe publish/subscribe event bus."""

    def __init__(self):
        self._subscribers: dict = defaultdict(list)
        self._lock = threading.Lock()

    def subscribe(self, event: str, handler: Callable):
        """Register a handler for an event type."""
        with self._lock:
            self._subscribers[event].append(handler)
        log.debug("Subscribed %s to event '%s'", handler.__name__, event)

    def publish(self, event: str, data: Any = None):
        """Dispatch an event to all registered handlers (in background threads)."""
        with self._lock:
            handlers = list(self._subscribers.get(event, []))
        for handler in handlers:
            t = threading.Thread(
                target=self._safe_call, args=(handler, event, data),
                daemon=True
            )
            t.start()

    def _safe_call(self, handler: Callable, event: str, data: Any):
        try:
            handler(data)
        except Exception as e:
            log.error("Event handler error [%s/%s]: %s", event, handler.__name__, e)


# Global event bus instance
bus = EventBus()

# ── Event Name Constants ──────────────────────────────────────
# Use these constants everywhere to avoid typo bugs

DEVICE_DISCOVERED    = "device.discovered"    # New device seen for the first time
DEVICE_UPDATED       = "device.updated"       # Known device re-seen
DEVICE_OFFLINE       = "device.offline"       # Device went offline
FLOW_CAPTURED        = "flow.captured"        # New traffic flow
DNS_QUERY_CAPTURED   = "dns.query"            # DNS query observed
ALERT_FIRED          = "alert.fired"          # Alert generated
BANDWIDTH_SAMPLE     = "bandwidth.sample"     # Bandwidth measurement
COLLECTION_COMPLETE  = "collection.complete"  # File collection finished
SCAN_COMPLETE        = "scan.complete"        # Network scan finished

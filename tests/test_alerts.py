"""NetWatch — Alert Engine Tests"""
import sys, os, time
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database import Database
from core.events   import EventBus


def make_engine(extra_config=None):
    config = {
        "network":  {"interface": "eth0", "subnet": "192.168.1.0/24", "gateway": "192.168.1.1"},
        "alerts":   {"enabled": True, "new_device": True, "port_scan_detection": True,
                     "bandwidth_spike_mbps": 10, "dns_anomaly": True},
        "dashboard": {"secret_key": "test"},
    }
    if extra_config:
        config.update(extra_config)
    db  = Database(":memory:")
    bus = EventBus()
    from modules.alerts.engine import AlertEngine
    eng = AlertEngine(config, db, bus)
    return db, bus, eng


def test_new_device_alert():
    db, bus, eng = make_engine()
    bus.publish("device.discovered", {
        "mac": "AA:BB:CC:00:00:01", "ip": "192.168.1.50",
        "vendor": "TestCorp", "hostname": None, "os_guess": None,
    })
    time.sleep(0.3)
    alerts = db.get_alerts()
    assert any(a.category == "new_device" for a in alerts)


def test_duplicate_device_no_alert():
    db, bus, eng = make_engine()
    payload = {"mac": "AA:BB:CC:00:00:02", "ip": "192.168.1.51",
               "vendor": "X", "hostname": None, "os_guess": None}
    bus.publish("device.discovered", payload)
    time.sleep(0.2)
    bus.publish("device.discovered", payload)  # second time — no new alert
    time.sleep(0.2)
    alerts = [a for a in db.get_alerts() if a.category == "new_device"]
    assert len(alerts) == 1


def test_port_scan_alert():
    db, bus, eng = make_engine()
    for port in range(1, 20):
        bus.publish("flow.captured", {
            "src_ip": "192.168.1.99", "dst_ip": "192.168.1.1",
            "src_port": 50000, "dst_port": port, "protocol": "TCP",
        })
    time.sleep(0.5)
    alerts = db.get_alerts()
    assert any(a.category == "port_scan" for a in alerts)


def test_dns_anomaly_alert():
    db, bus, eng = make_engine()
    bus.publish("dns.query", {
        "src_ip": "192.168.1.5", "domain": "evil.botnet.ru.com",
        "qtype": "A", "flagged": True,
    })
    time.sleep(0.3)
    alerts = db.get_alerts()
    assert any(a.category == "dns_anomaly" for a in alerts)

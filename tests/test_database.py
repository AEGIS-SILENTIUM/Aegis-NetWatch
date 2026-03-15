"""
NetWatch — Database Tests

DISCLAIMER: For authorized use on networks/devices you own only.
"""
import pytest
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.database import Database


@pytest.fixture
def db():
    """In-memory test database."""
    d = Database(":memory:")
    yield d


def test_upsert_device_new(db):
    dev = db.upsert_device(mac="AA:BB:CC:DD:EE:FF", ip="192.168.1.10", vendor="Test Vendor")
    assert dev.mac == "AA:BB:CC:DD:EE:FF"
    assert dev.ip  == "192.168.1.10"
    assert dev.vendor == "Test Vendor"


def test_upsert_device_update(db):
    db.upsert_device(mac="AA:BB:CC:DD:EE:FF", ip="192.168.1.10")
    db.upsert_device(mac="AA:BB:CC:DD:EE:FF", ip="192.168.1.11", hostname="mypc")
    devs = db.get_all_devices()
    assert len(devs) == 1
    assert devs[0].ip == "192.168.1.11"
    assert devs[0].hostname == "mypc"


def test_get_all_devices(db):
    db.upsert_device(mac="AA:BB:CC:DD:EE:F1", ip="192.168.1.1")
    db.upsert_device(mac="AA:BB:CC:DD:EE:F2", ip="192.168.1.2")
    devs = db.get_all_devices()
    assert len(devs) == 2


def test_mark_devices_inactive(db):
    db.upsert_device(mac="AA:BB:CC:DD:EE:F1", ip="192.168.1.1", is_active=True)
    db.upsert_device(mac="AA:BB:CC:DD:EE:F2", ip="192.168.1.2", is_active=True)
    db.mark_devices_inactive(["AA:BB:CC:DD:EE:F1"])
    devs = db.get_all_devices()
    mac_status = {d.mac: d.is_active for d in devs}
    assert mac_status["AA:BB:CC:DD:EE:F1"] == True   # still active (in list)
    assert mac_status["AA:BB:CC:DD:EE:F2"] == False  # marked inactive


def test_add_and_get_flow(db):
    db.add_flow(src_ip="192.168.1.1", dst_ip="8.8.8.8", protocol="UDP", bytes_sent=100)
    flows = db.get_recent_flows(minutes=5)
    assert len(flows) == 1
    assert flows[0].src_ip == "192.168.1.1"


def test_add_and_get_dns(db):
    db.add_dns_query(src_ip="192.168.1.5", domain="example.com", qtype="A")
    queries = db.get_recent_dns(minutes=60)
    assert len(queries) == 1
    assert queries[0].domain == "example.com"


def test_dns_flagging(db):
    db.add_dns_query(src_ip="192.168.1.5", domain="malware.botnet.ru.com", qtype="A", flagged=True)
    queries = db.get_recent_dns(minutes=60)
    assert queries[0].flagged == True


def test_add_and_get_alert(db):
    db.add_alert(severity="HIGH", category="new_device", title="Test alert")
    alerts = db.get_alerts()
    assert len(alerts) == 1
    assert alerts[0].severity == "HIGH"


def test_acknowledge_alert(db):
    alert = db.add_alert(severity="LOW", category="test", title="Ack test")
    assert db.acknowledge_alert(alert.id) == True
    alerts = db.get_alerts(unacked_only=True)
    assert len(alerts) == 0


def test_acknowledge_missing_alert(db):
    assert db.acknowledge_alert(9999) == False


def test_add_bandwidth_sample(db):
    db.add_bandwidth_sample(device_ip="192.168.1.1", bytes_in=1000, bytes_out=500)
    samples = db.get_bandwidth_history("192.168.1.1", hours=1)
    assert len(samples) == 1
    assert samples[0].bytes_in == 1000


def test_get_stats(db):
    db.upsert_device(mac="AA:BB:CC:DD:EE:F1", ip="192.168.1.1", is_active=True)
    db.add_alert(severity="MEDIUM", category="test", title="t")
    stats = db.get_stats()
    assert stats["total_devices"]  == 1
    assert stats["unacked_alerts"] == 1


def test_device_to_dict(db):
    dev = db.upsert_device(mac="AA:BB:CC:DD:EE:FF", ip="192.168.1.10")
    d   = dev.to_dict()
    assert "mac"        in d
    assert "ip"         in d
    assert "first_seen" in d
    assert "open_ports" in d
    assert isinstance(d["open_ports"], list)


def test_purge_old_data(db):
    from datetime import datetime, timedelta
    from core.database import TrafficFlow
    # Insert old flow
    with db.Session() as s:
        s.add(TrafficFlow(
            src_ip="1.1.1.1", dst_ip="2.2.2.2",
            timestamp=datetime.utcnow() - timedelta(days=60)
        ))
        s.commit()
    flows_before = db.get_recent_flows(minutes=999999)
    assert len(flows_before) == 1
    db.purge_old_data(retention_days=30)
    flows_after = db.get_recent_flows(minutes=999999)
    assert len(flows_after) == 0

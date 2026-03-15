"""
NetWatch — Database Layer
SQLite storage for all network monitoring data.

DISCLAIMER: For authorized use on networks/devices you own only.
"""
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Any

from sqlalchemy import (
    create_engine, Column, String, Integer, DateTime,
    Boolean, Text, JSON, Index, event
)
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy.pool import StaticPool

log = logging.getLogger("netwatch.db")
Base = declarative_base()


class Device(Base):
    __tablename__ = "devices"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    mac         = Column(String(17), unique=True, nullable=False, index=True)
    ip          = Column(String(45))
    hostname    = Column(String(255))
    vendor      = Column(String(255))
    os_guess    = Column(String(255))
    open_ports  = Column(JSON)
    first_seen  = Column(DateTime, default=datetime.utcnow)
    last_seen   = Column(DateTime, default=datetime.utcnow)
    is_active   = Column(Boolean, default=True)
    tags        = Column(JSON, default=list)
    notes       = Column(Text)

    def to_dict(self):
        return {
            "id": self.id, "mac": self.mac, "ip": self.ip,
            "hostname": self.hostname, "vendor": self.vendor,
            "os_guess": self.os_guess, "open_ports": self.open_ports or [],
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen":  self.last_seen.isoformat()  if self.last_seen  else None,
            "is_active": self.is_active, "tags": self.tags or [], "notes": self.notes,
        }


class TrafficFlow(Base):
    __tablename__ = "traffic_flows"
    __table_args__ = (Index("ix_flows_time", "timestamp"),)
    id         = Column(Integer, primary_key=True, autoincrement=True)
    timestamp  = Column(DateTime, default=datetime.utcnow, index=True)
    src_ip     = Column(String(45), nullable=False)
    dst_ip     = Column(String(45), nullable=False)
    src_port   = Column(Integer)
    dst_port   = Column(Integer)
    protocol   = Column(String(10))
    bytes_sent = Column(Integer, default=0)
    packets    = Column(Integer, default=1)
    service    = Column(String(50))

    def to_dict(self):
        return {
            "id": self.id, "timestamp": self.timestamp.isoformat(),
            "src_ip": self.src_ip, "dst_ip": self.dst_ip,
            "src_port": self.src_port, "dst_port": self.dst_port,
            "protocol": self.protocol, "bytes_sent": self.bytes_sent,
            "packets": self.packets, "service": self.service,
        }


class DnsQuery(Base):
    __tablename__ = "dns_queries"
    __table_args__ = (Index("ix_dns_time", "timestamp"),)
    id        = Column(Integer, primary_key=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    src_ip    = Column(String(45), nullable=False, index=True)
    domain    = Column(String(255), nullable=False, index=True)
    qtype     = Column(String(10))
    response  = Column(Text)
    flagged   = Column(Boolean, default=False)

    def to_dict(self):
        return {
            "id": self.id, "timestamp": self.timestamp.isoformat(),
            "src_ip": self.src_ip, "domain": self.domain,
            "qtype": self.qtype, "response": self.response, "flagged": self.flagged,
        }


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (Index("ix_alerts_time", "timestamp"),)
    id           = Column(Integer, primary_key=True, autoincrement=True)
    timestamp    = Column(DateTime, default=datetime.utcnow, index=True)
    severity     = Column(String(10), nullable=False)
    category     = Column(String(50), nullable=False)
    title        = Column(String(255), nullable=False)
    description  = Column(Text)
    device_mac   = Column(String(17))
    device_ip    = Column(String(45))
    acknowledged = Column(Boolean, default=False)
    extra_data   = Column(JSON)

    def to_dict(self):
        return {
            "id": self.id, "timestamp": self.timestamp.isoformat(),
            "severity": self.severity, "category": self.category,
            "title": self.title, "description": self.description,
            "device_mac": self.device_mac, "device_ip": self.device_ip,
            "acknowledged": self.acknowledged, "extra_data": self.extra_data,
        }


class BandwidthSample(Base):
    __tablename__ = "bandwidth_samples"
    id         = Column(Integer, primary_key=True, autoincrement=True)
    timestamp  = Column(DateTime, default=datetime.utcnow, index=True)
    device_ip  = Column(String(45), nullable=False, index=True)
    device_mac = Column(String(17))
    bytes_in   = Column(Integer, default=0)
    bytes_out  = Column(Integer, default=0)

    def to_dict(self):
        return {
            "timestamp": self.timestamp.isoformat(), "device_ip": self.device_ip,
            "device_mac": self.device_mac, "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
        }


class CollectedFile(Base):
    __tablename__ = "collected_files"
    id          = Column(Integer, primary_key=True, autoincrement=True)
    timestamp   = Column(DateTime, default=datetime.utcnow)
    device_name = Column(String(255), nullable=False)
    device_host = Column(String(45), nullable=False)
    remote_path = Column(String(1024), nullable=False)
    local_path  = Column(String(1024), nullable=False)
    size_bytes  = Column(Integer, default=0)
    success     = Column(Boolean, default=True)
    error_msg   = Column(Text)

    def to_dict(self):
        return {
            "id": self.id, "timestamp": self.timestamp.isoformat(),
            "device_name": self.device_name, "device_host": self.device_host,
            "remote_path": self.remote_path, "local_path": self.local_path,
            "size_bytes": self.size_bytes, "success": self.success, "error_msg": self.error_msg,
        }


class Database:
    """Thread-safe SQLite database manager."""

    def __init__(self, db_path: str = "data/netwatch.db"):
        import os
        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
        self.engine = create_engine(
            f"sqlite:///{db_path}",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
        )
        @event.listens_for(self.engine, "connect")
        def set_pragmas(conn, _):
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")

        Base.metadata.create_all(self.engine)
        self.Session = sessionmaker(bind=self.engine, expire_on_commit=False)
        log.info("Database ready at %s", db_path)

    # ── Devices ──
    def upsert_device(self, mac: str, **kw) -> Device:
        with self.Session() as s:
            dev = s.query(Device).filter_by(mac=mac).first()
            if dev is None:
                dev = Device(mac=mac, **kw)
                s.add(dev)
            else:
                for k, v in kw.items():
                    if v is not None:
                        setattr(dev, k, v)
                dev.last_seen = datetime.utcnow()
            s.commit(); s.refresh(dev)
            return dev

    def get_all_devices(self) -> List[Device]:
        with self.Session() as s:
            return s.query(Device).order_by(Device.last_seen.desc()).all()

    def get_active_devices(self) -> List[Device]:
        cutoff = datetime.utcnow() - timedelta(minutes=10)
        with self.Session() as s:
            return s.query(Device).filter(Device.last_seen >= cutoff).all()

    def mark_devices_inactive(self, active_macs: List[str]):
        with self.Session() as s:
            s.query(Device).filter(Device.mac.notin_(active_macs)).update(
                {"is_active": False}, synchronize_session=False)
            s.commit()

    # ── Flows ──
    def add_flow(self, **kw) -> TrafficFlow:
        with self.Session() as s:
            f = TrafficFlow(**kw); s.add(f); s.commit(); return f

    def get_recent_flows(self, minutes: int = 5, limit: int = 500) -> List[TrafficFlow]:
        cutoff = datetime.utcnow() - timedelta(minutes=minutes)
        with self.Session() as s:
            return s.query(TrafficFlow).filter(
                TrafficFlow.timestamp >= cutoff
            ).order_by(TrafficFlow.timestamp.desc()).limit(limit).all()

    def get_flows_by_ip(self, ip: str, limit: int = 200) -> List[TrafficFlow]:
        with self.Session() as s:
            return s.query(TrafficFlow).filter(
                (TrafficFlow.src_ip == ip) | (TrafficFlow.dst_ip == ip)
            ).order_by(TrafficFlow.timestamp.desc()).limit(limit).all()

    # ── DNS ──
    def add_dns_query(self, **kw) -> DnsQuery:
        with self.Session() as s:
            q = DnsQuery(**kw); s.add(q); s.commit(); return q

    def get_recent_dns(self, minutes: int = 60, limit: int = 1000) -> List[DnsQuery]:
        cutoff = datetime.utcnow() - timedelta(minutes=minutes)
        with self.Session() as s:
            return s.query(DnsQuery).filter(
                DnsQuery.timestamp >= cutoff
            ).order_by(DnsQuery.timestamp.desc()).limit(limit).all()

    def get_dns_by_device(self, ip: str, limit: int = 200) -> List[DnsQuery]:
        with self.Session() as s:
            return s.query(DnsQuery).filter_by(src_ip=ip).order_by(
                DnsQuery.timestamp.desc()).limit(limit).all()

    # ── Alerts ──
    def add_alert(self, **kw) -> Alert:
        with self.Session() as s:
            a = Alert(**kw); s.add(a); s.commit()
            log.info("ALERT [%s] %s", kw.get("severity"), kw.get("title"))
            return a

    def get_alerts(self, limit: int = 100, unacked_only: bool = False) -> List[Alert]:
        with self.Session() as s:
            q = s.query(Alert)
            if unacked_only:
                q = q.filter_by(acknowledged=False)
            return q.order_by(Alert.timestamp.desc()).limit(limit).all()

    def acknowledge_alert(self, alert_id: int) -> bool:
        with self.Session() as s:
            a = s.query(Alert).filter_by(id=alert_id).first()
            if a:
                a.acknowledged = True; s.commit(); return True
            return False

    # ── Bandwidth ──
    def add_bandwidth_sample(self, **kw):
        with self.Session() as s:
            s.add(BandwidthSample(**kw)); s.commit()

    def get_bandwidth_history(self, device_ip: str, hours: int = 1) -> List[BandwidthSample]:
        cutoff = datetime.utcnow() - timedelta(hours=hours)
        with self.Session() as s:
            return s.query(BandwidthSample).filter(
                BandwidthSample.device_ip == device_ip,
                BandwidthSample.timestamp >= cutoff,
            ).order_by(BandwidthSample.timestamp.asc()).all()

    # ── Collector ──
    def add_collected_file(self, **kw) -> CollectedFile:
        with self.Session() as s:
            f = CollectedFile(**kw); s.add(f); s.commit(); return f

    def get_collected_files(self, limit: int = 100) -> List[CollectedFile]:
        with self.Session() as s:
            return s.query(CollectedFile).order_by(
                CollectedFile.timestamp.desc()).limit(limit).all()

    # ── Maintenance ──
    def purge_old_data(self, retention_days: int = 30):
        cutoff = datetime.utcnow() - timedelta(days=retention_days)
        with self.Session() as s:
            f = s.query(TrafficFlow).filter(TrafficFlow.timestamp < cutoff).delete()
            d = s.query(DnsQuery).filter(DnsQuery.timestamp < cutoff).delete()
            a = s.query(Alert).filter(Alert.timestamp < cutoff, Alert.acknowledged == True).delete()
            b = s.query(BandwidthSample).filter(BandwidthSample.timestamp < cutoff).delete()
            s.commit()
            log.info("Purged %d flows, %d dns, %d alerts, %d bw samples", f, d, a, b)

    def get_stats(self) -> Dict[str, int]:
        with self.Session() as s:
            return {
                "total_devices":  s.query(Device).count(),
                "active_devices": s.query(Device).filter_by(is_active=True).count(),
                "total_flows":    s.query(TrafficFlow).count(),
                "total_dns":      s.query(DnsQuery).count(),
                "unacked_alerts": s.query(Alert).filter_by(acknowledged=False).count(),
            }

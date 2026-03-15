"""
NetWatch — Device Data Collector
Collects files and data from YOUR OWN devices via SSH.
Requires you to have SSH credentials (key or password) for your own devices.

DISCLAIMER: This module is for collecting data from devices you OWN.
Never use against devices you do not own or have explicit authorization for.
Unauthorized access to computer systems is a criminal offense.
"""
import logging
import os
import time
import threading
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Optional

log = logging.getLogger("netwatch.collector")


class SSHCollector:
    """
    SSH-based file collector for your own devices.
    Uses paramiko for SSH connections.
    Supports key-based and password authentication.
    """

    def __init__(self, config: dict, db, event_bus):
        self.config  = config
        self.db      = db
        self.bus     = event_bus
        self.cc      = config.get("collector", {})
        self.devices = self.cc.get("devices", [])
        self.output_dir = Path("data/collected")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def _connect(self, device: dict):
        """Create an SSH connection to a device you own."""
        try:
            import paramiko
        except ImportError:
            log.error("paramiko not installed. Install with: pip3 install paramiko")
            return None

        host     = device["host"]
        username = device.get("username", os.getenv("USER", "admin"))
        key_file = device.get("key_file")
        password = device.get("password")
        port     = device.get("port", 22)

        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        try:
            if key_file:
                expanded_key = os.path.expanduser(key_file)
                client.connect(
                    hostname=host, port=port, username=username,
                    key_filename=expanded_key, timeout=10,
                    look_for_keys=False,
                )
            elif password:
                client.connect(
                    hostname=host, port=port, username=username,
                    password=password, timeout=10,
                    look_for_keys=False,
                )
            else:
                # Try SSH agent / default keys
                client.connect(hostname=host, port=port, username=username, timeout=10)

            log.info("SSH connected to %s@%s", username, host)
            return client
        except Exception as e:
            log.error("SSH connection failed to %s: %s", host, e)
            client.close()
            return None

    def collect_device(self, device: dict) -> List[Dict]:
        """Collect all configured paths from a single device."""
        results = []
        name    = device.get("name", device["host"])
        host    = device["host"]
        paths   = device.get("paths", [])

        if not paths:
            log.warning("No paths configured for device %s", name)
            return results

        client = self._connect(device)
        if not client:
            return results

        # Device-specific output directory
        dev_dir = self.output_dir / name.replace(" ", "_") / datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        dev_dir.mkdir(parents=True, exist_ok=True)

        try:
            sftp = client.open_sftp()
            for remote_path in paths:
                local_name = Path(remote_path).name
                local_path = str(dev_dir / local_name)

                start = time.time()
                success   = True
                error_msg = None
                size      = 0

                try:
                    sftp.get(remote_path, local_path)
                    size = os.path.getsize(local_path)
                    elapsed = time.time() - start
                    log.info("Collected %s from %s (%d bytes, %.1fs)", remote_path, name, size, elapsed)
                except Exception as e:
                    success   = False
                    error_msg = str(e)
                    log.warning("Failed to collect %s from %s: %s", remote_path, name, e)

                rec = self.db.add_collected_file(
                    device_name=name,
                    device_host=host,
                    remote_path=remote_path,
                    local_path=local_path,
                    size_bytes=size,
                    success=success,
                    error_msg=error_msg,
                )
                results.append(rec.to_dict())

            sftp.close()
        except Exception as e:
            log.error("SFTP error for %s: %s", name, e)
        finally:
            client.close()

        return results

    def collect_all(self) -> List[Dict]:
        """Run collection on all configured devices."""
        if not self.cc.get("enabled", False):
            log.info("Collector disabled in config")
            return []

        all_results = []
        for device in self.devices:
            try:
                results = self.collect_device(device)
                all_results.extend(results)
            except Exception as e:
                log.error("Collection error for %s: %s", device.get("name", "?"), e)

        self.bus.publish("collection.complete", {"collected": len(all_results)})
        return all_results

    def run_scheduled(self, interval_hours: int = 24):
        """Run collection on a schedule (default: daily)."""
        def _loop():
            while True:
                try:
                    self.collect_all()
                except Exception as e:
                    log.error("Scheduled collection error: %s", e)
                time.sleep(interval_hours * 3600)

        t = threading.Thread(target=_loop, daemon=True, name="collector")
        t.start()
        log.info("Scheduled collection started (every %dh)", interval_hours)

    def list_remote_directory(self, device: dict, remote_path: str) -> List[Dict]:
        """List contents of a remote directory on your own device."""
        client = self._connect(device)
        if not client:
            return []
        try:
            sftp  = client.open_sftp()
            items = []
            for attr in sftp.listdir_attr(remote_path):
                items.append({
                    "name":     attr.filename,
                    "size":     attr.st_size,
                    "modified": datetime.fromtimestamp(attr.st_mtime).isoformat() if attr.st_mtime else None,
                    "is_dir":   bool(attr.st_mode & 0o40000),
                })
            sftp.close()
            return items
        except Exception as e:
            log.error("Directory listing error: %s", e)
            return []
        finally:
            client.close()

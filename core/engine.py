"""
NetWatch — Orchestration Engine
Initializes and coordinates all modules.

DISCLAIMER: Use only on networks/devices you own or are authorized to monitor.
"""
import logging
import os
import yaml
from pathlib import Path

log = logging.getLogger("netwatch.engine")


def load_config(path: str = "configs/config.yaml") -> dict:
    """Load and validate YAML configuration."""
    if not os.path.exists(path):
        example = path.replace("config.yaml", "config.example.yaml")
        if os.path.exists(example):
            import shutil
            shutil.copy(example, path)
            log.warning("Config not found. Copied example config to %s — please review!", path)
        else:
            raise FileNotFoundError(f"Config file not found: {path}")

    with open(path, "r") as f:
        cfg = yaml.safe_load(f)

    # Validate required fields
    required = [
        ("network", "interface"),
        ("network", "subnet"),
    ]
    for section, key in required:
        if not cfg.get(section, {}).get(key):
            raise ValueError(f"Missing required config: {section}.{key}")

    return cfg


class NetWatchEngine:
    """
    Top-level orchestrator. Creates all modules and wires them together.
    """

    def __init__(self, config_path: str = "configs/config.yaml"):
        self.config = load_config(config_path)
        self._setup_logging()

        from core.database import Database
        from core.events   import EventBus

        self.db  = Database(self.config.get("database", {}).get("path", "data/netwatch.db"))
        self.bus = EventBus()

        self._init_modules()

    def _setup_logging(self):
        cfg = self.config.get("logging", {})
        level = getattr(logging, cfg.get("level", "INFO").upper(), logging.INFO)
        log_file = cfg.get("file", "data/netwatch.log")
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)

        logging.basicConfig(
            level=level,
            format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler(log_file),
            ],
        )

    def _init_modules(self):
        from modules.discovery.scanner       import NetworkScanner
        from modules.traffic.monitor         import TrafficMonitor
        from modules.dns.logger              import DnsLogger
        from modules.alerts.engine           import AlertEngine
        from modules.collector.ssh_collector import SSHCollector

        self.scanner   = NetworkScanner(self.config, self.db, self.bus)
        self.traffic   = TrafficMonitor(self.config, self.db, self.bus)
        self.dns       = DnsLogger(self.config, self.db, self.bus)
        self.alerts    = AlertEngine(self.config, self.db, self.bus)
        self.collector = SSHCollector(self.config, self.db, self.bus)

        log.info("All modules initialized")

    def start(self):
        """Start all background modules."""
        log.info("NetWatch starting up...")
        self.scanner.start_continuous()
        self.traffic.start()
        self.dns.start()
        if self.config.get("collector", {}).get("enabled"):
            self.collector.run_scheduled()
        log.info("NetWatch running. Dashboard: http://%s:%d",
                 self.config["dashboard"].get("host", "127.0.0.1"),
                 self.config["dashboard"].get("port", 8080))

    def stop(self):
        self.scanner.stop()
        self.traffic.stop()
        self.dns.stop()
        log.info("NetWatch stopped")

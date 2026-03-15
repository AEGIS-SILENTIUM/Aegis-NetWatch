#!/usr/bin/env python3
"""
NetWatch — Personal Network Monitoring Toolkit
Main entry point.

DISCLAIMER: For authorized use on networks and devices you own only.
Unauthorized network monitoring is illegal in most jurisdictions.

Usage:
    sudo python3 netwatch.py                    # Run with default config
    sudo python3 netwatch.py --config my.yaml  # Custom config
    python3 netwatch.py --check                 # Check dependencies only
    python3 netwatch.py --scan-once            # Run one scan and exit
"""
import argparse
import logging
import os
import sys
import subprocess
import threading
import time

log = logging.getLogger("netwatch")


def check_root():
    """Warn if not running as root (required for packet capture)."""
    if os.geteuid() != 0:
        print("⚠  WARNING: Not running as root. Packet capture requires root/sudo.")
        print("   Run: sudo python3 netwatch.py")
        print()


def check_dependencies() -> bool:
    """Check that required system tools are installed."""
    ok = True
    tools = {
        "nmap":     "sudo apt-get install nmap",
        "tshark":   "sudo apt-get install tshark",
        "arp-scan": "sudo apt-get install arp-scan",
    }
    print("Checking dependencies...")
    for tool, install_hint in tools.items():
        try:
            subprocess.run(["which", tool], capture_output=True, check=True)
            print(f"  ✓ {tool}")
        except subprocess.CalledProcessError:
            print(f"  ✗ {tool} not found — install with: {install_hint}")
            ok = False

    # Check Python packages
    py_packages = ["flask", "flask_socketio", "scapy", "nmap", "sqlalchemy", "yaml", "paramiko"]
    for pkg in py_packages:
        try:
            __import__(pkg)
            print(f"  ✓ python:{pkg}")
        except ImportError:
            print(f"  ✗ python:{pkg} — run: pip3 install -r requirements.txt")
            ok = False

    print()
    if ok:
        print("✓ All dependencies satisfied.")
    else:
        print("✗ Some dependencies missing. Fix above and retry.")
    return ok


def print_banner():
    print("""
╔══════════════════════════════════════════════════════════╗
║          🛰  NetWatch — Personal Network Monitor          ║
║                      Version 1.0.0                       ║
╠══════════════════════════════════════════════════════════╣
║  ⚠  AUTHORIZED USE ONLY — Your network, your devices     ║
║     Unauthorized monitoring is illegal.                  ║
╚══════════════════════════════════════════════════════════╝
""")


def main():
    parser = argparse.ArgumentParser(description="NetWatch — Personal Network Monitor")
    parser.add_argument("--config",    default="configs/config.yaml", help="Config file path")
    parser.add_argument("--check",     action="store_true",           help="Check dependencies and exit")
    parser.add_argument("--scan-once", action="store_true",           help="Run one scan and exit")
    args = parser.parse_args()

    print_banner()

    if args.check:
        sys.exit(0 if check_dependencies() else 1)

    check_root()

    # Initialize engine
    try:
        from core.engine import NetWatchEngine
        engine = NetWatchEngine(config_path=args.config)
    except FileNotFoundError as e:
        print(f"ERROR: {e}")
        print("Copy configs/config.example.yaml to configs/config.yaml and edit it.")
        sys.exit(1)
    except ValueError as e:
        print(f"CONFIG ERROR: {e}")
        sys.exit(1)

    if args.scan_once:
        results = engine.scanner.scan_once()
        print(f"\nFound {len(results)} device(s):")
        for d in results:
            print(f"  {d['ip']:18} {d['mac']}  {d['vendor'] or 'Unknown':30} {d['hostname'] or ''}")
        sys.exit(0)

    # Start all background modules
    engine.start()

    # Start web dashboard in the main thread (blocking)
    cfg = engine.config
    from dashboard.app import run_dashboard
    try:
        run_dashboard(engine.db, engine.bus, cfg)
    except KeyboardInterrupt:
        print("\n\nShutting down NetWatch...")
        engine.stop()
        sys.exit(0)


if __name__ == "__main__":
    main()

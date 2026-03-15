#!/usr/bin/env python3
"""
NetWatch — Export Report
Generates a summary report of all network activity.

DISCLAIMER: For authorized use on networks/devices you own only.
Usage: python3 scripts/export_report.py [--db data/netwatch.db]
"""
import sys, os, argparse
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--db", default="data/netwatch.db")
    args = parser.parse_args()

    from core.database import Database
    db = Database(args.db)

    print("=" * 60)
    print("  NetWatch Network Report")
    print("=" * 60)

    stats = db.get_stats()
    print(f"\nSummary:")
    print(f"  Total devices ever seen:  {stats['total_devices']}")
    print(f"  Active devices (10m):     {stats['active_devices']}")
    print(f"  Traffic flows recorded:  {stats['total_flows']}")
    print(f"  DNS queries logged:      {stats['total_dns']}")
    print(f"  Unacknowledged alerts:   {stats['unacked_alerts']}")

    print(f"\nAll Devices:")
    print(f"  {'IP':<18} {'MAC':<20} {'Hostname':<25} {'Vendor':<25} {'Status'}")
    print(f"  {'-'*18} {'-'*20} {'-'*25} {'-'*25} {'-'*8}")
    for d in db.get_all_devices():
        status = "Active" if d.is_active else "Offline"
        print(f"  {d.ip or '—':<18} {d.mac:<20} {(d.hostname or '—'):<25} {(d.vendor or 'Unknown'):<25} {status}")

    print(f"\nRecent Alerts (unacknowledged):")
    for a in db.get_alerts(limit=20, unacked_only=True):
        print(f"  [{a.severity:8}] {a.category:20} {a.title}")

    print(f"\nTop DNS Domains (last 24h):")
    from collections import Counter
    queries = db.get_recent_dns(minutes=1440, limit=10000)
    for domain, count in Counter(q.domain for q in queries).most_common(10):
        print(f"  {count:6}  {domain}")

if __name__ == "__main__":
    main()

# Configuration Reference

> ⚠️ **DISCLAIMER**: All configuration options apply only to networks and devices you own.

---

## network

| Key | Default | Description |
|-----|---------|-------------|
| `interface` | required | Network interface (e.g. `wlan0`, `eth0`, `en0`) |
| `subnet` | required | CIDR notation (e.g. `192.168.1.0/24`) |
| `gateway` | required | Router IP address |

## discovery

| Key | Default | Description |
|-----|---------|-------------|
| `interval` | 60 | Seconds between ARP scans |
| `os_fingerprint` | true | Enable Nmap OS detection |
| `port_scan` | true | Enable port scanning |
| `ports` | common ports | Port list for Nmap |

## traffic

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | true | Enable packet capture |
| `filter` | "" | BPF capture filter |
| `buffer_size` | 10000 | Max packets in memory |
| `save_pcap` | false | Save raw PCAP files |

## dns

| Key | Default | Description |
|-----|---------|-------------|
| `enabled` | true | Enable DNS sniffing |

## alerts

| Key | Default | Description |
|-----|---------|-------------|
| `new_device` | true | Alert on new device |
| `port_scan_detection` | true | Detect port scans |
| `bandwidth_spike_mbps` | 50 | Threshold for spike alert |
| `dns_anomaly` | true | Flag suspicious DNS |
| `webhook_url` | "" | POST alerts to this URL |

## dashboard

| Key | Default | Description |
|-----|---------|-------------|
| `host` | 127.0.0.1 | Listen address (use 0.0.0.0 for LAN access) |
| `port` | 8080 | HTTP port |
| `secret_key` | required | Change to random string |
| `auth_enabled` | false | Require login |

## database

| Key | Default | Description |
|-----|---------|-------------|
| `path` | data/netwatch.db | SQLite file path |
| `retention_days` | 30 | Days to keep data |

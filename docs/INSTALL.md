# Installation Guide

> ⚠️ **DISCLAIMER**: NetWatch is for use only on networks and devices you own or have explicit written authorization to monitor. Unauthorized network monitoring is illegal in most jurisdictions, including the Philippines Cybercrime Prevention Act (RA 10175) and the US Computer Fraud and Abuse Act.

---

## System Requirements

- **OS**: Linux (Ubuntu 20.04+, Debian 11+, Kali) or macOS 12+
- **Python**: 3.9 or newer
- **RAM**: 512 MB minimum (2 GB recommended for large networks)
- **Privileges**: Root/sudo required for packet capture

---

## Step 1 — Install System Tools

### Ubuntu / Debian
```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip nmap tshark arp-scan
# Allow non-root tshark (optional, captures still need root for raw sockets)
sudo dpkg-reconfigure wireshark-common
sudo usermod -aG wireshark $USER
```

### macOS (Homebrew)
```bash
brew install python nmap wireshark
pip3 install scapy
```

---

## Step 2 — Install Python Dependencies

```bash
cd NetWatch
pip3 install -r requirements.txt
```

---

## Step 3 — Configure

```bash
cp configs/config.example.yaml configs/config.yaml
nano configs/config.yaml
```

**Minimum required settings:**
```yaml
network:
  interface: "wlan0"         # Find yours with: ip link show
  subnet: "192.168.1.0/24"  # Your home network
  gateway: "192.168.1.1"    # Your router
```

**Find your interface:**
```bash
ip link show       # Linux
ifconfig           # macOS
```

---

## Step 4 — Run

```bash
# Check dependencies
python3 netwatch.py --check

# Run (requires root for packet capture)
sudo python3 netwatch.py

# Open dashboard
# http://127.0.0.1:8080
```

---

## Running as a Service (systemd)

```ini
# /etc/systemd/system/netwatch.service
[Unit]
Description=NetWatch Network Monitor
After=network.target

[Service]
WorkingDirectory=/opt/NetWatch
ExecStart=/usr/bin/python3 netwatch.py
Restart=on-failure
User=root

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable netwatch
sudo systemctl start netwatch
sudo journalctl -u netwatch -f
```

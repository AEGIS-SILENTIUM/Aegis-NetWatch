# NetWatch — Personal Network Monitoring Toolkit

> **Version 1.0.0 | Production-Ready**

---

## ⚠️ LEGAL DISCLAIMER — READ BEFORE USE

> **THIS TOOL IS DESIGNED EXCLUSIVELY FOR USE ON NETWORKS AND DEVICES YOU OWN OR HAVE EXPLICIT WRITTEN AUTHORIZATION TO MONITOR.**
>
> Unauthorized interception of network traffic, unauthorized access to computer systems, and unauthorized collection of data from devices you do not own are **serious criminal offenses** in most jurisdictions, including:
>
> - **United States**: Computer Fraud and Abuse Act (CFAA), Electronic Communications Privacy Act (ECPA), Wiretap Act
> - **European Union**: General Data Protection Regulation (GDPR), NIS2 Directive
> - **Philippines**: Cybercrime Prevention Act of 2012 (RA 10175), Data Privacy Act (RA 10173)
> - **United Kingdom**: Computer Misuse Act 1990, Investigatory Powers Act 2016
>
> **By using this software, you affirm:**
> 1. You own or have explicit written authorization to monitor the target network.
> 2. You own or have explicit consent from owners of all monitored devices.
> 3. You will comply with all applicable local, national, and international laws.
> 4. The authors bear ZERO liability for any misuse of this software.
>
> **Use responsibly. Use legally. Use ethically.**

---

## What Is NetWatch?

NetWatch is a fully offline, self-hosted network monitoring platform giving you complete visibility into your own Wi-Fi network:

- Every connected device: IP, MAC, hostname, vendor, OS fingerprint
- All traffic flows between devices — who talks to whom, on what ports
- All DNS queries from every device on the network
- Real-time configurable alerts (new device, port scan, traffic spike)
- Data collection from your own devices via SSH
- Live web dashboard with charts, tables, and export

---

## Features

| Module | Capability |
|--------|------------|
| Discovery | ARP scan, Nmap OS fingerprint, vendor lookup, port scan |
| Traffic Monitor | Packet capture via tshark, flow analysis, protocol breakdown |
| DNS Logger | All DNS queries logged per device with timestamps |
| Device Collector | SSH-based file/data pull from your own devices |
| Alert Engine | Rule-based: new device, port scan, bandwidth spike, DNS anomaly |
| Dashboard | Live Flask web UI — devices, flows, DNS log, alerts, charts |

---

## Quick Start

```bash
# Install system dependencies (Linux)
sudo apt-get install nmap tshark arp-scan python3-pip

# Install Python dependencies
pip3 install -r requirements.txt

# Configure
cp configs/config.example.yaml configs/config.yaml
# Edit configs/config.yaml — set your interface (e.g. wlan0) and subnet

# Run (requires root for packet capture)
sudo python3 netwatch.py

# Open dashboard
# http://localhost:8080
```

---

## Requirements

- Python 3.9+
- Linux (recommended) or macOS
- nmap, tshark, arp-scan installed
- Root/sudo (required for raw packet capture)

---

## License

MIT License — see LICENSE

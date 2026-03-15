# NetWatch v2.0 — Android Termux Installation Guide

> ⚠️ **LEGAL DISCLAIMER**: NetWatch is for authorized use ONLY on networks and devices
> you own or have explicit written authorization to monitor. Unauthorized network
> monitoring is a criminal offense under Philippine law (RA 10175), the US CFAA,
> EU GDPR/NIS2, and most other jurisdictions. Use responsibly.

---

## What Works on Termux (Non-Rooted)

| Feature | Non-Rooted | Rooted |
|---------|-----------|--------|
| Device discovery (ARP + /proc/net/arp) | ✅ | ✅ |
| Nmap port scan | ✅ | ✅ |
| DNS logging (passive sniff) | ✅* | ✅ |
| Traffic capture (tshark/tcpdump) | ✅* | ✅ |
| ARP spoof detection | ✅ | ✅ |
| Web dashboard | ✅ | ✅ |
| Bandwidth tracking | ✅ | ✅ |
| Alert engine (all rules) | ✅ | ✅ |
| SSH device collector | ✅ | ✅ |
| Geo IP lookup | ✅ | ✅ |

*May require `termux-setup-storage` or Termux:API for some features on certain devices.

---

## Step 1 — Install Termux

Install **Termux from F-Droid** (not Google Play — the Play version is outdated):
- Download from: https://f-droid.org/packages/com.termux/

---

## Step 2 — Install System Packages

Open Termux and run:

```bash
# Update package lists
pkg update && pkg upgrade -y

# Core tools
pkg install -y python nmap tshark tcpdump

# Optional but recommended
pkg install -y arp-scan openssh tmux git nano wget

# Storage access (needed to save reports to your phone)
termux-setup-storage
```

> **Note**: If tshark is not available in your Termux repo:
> ```bash
> pkg install -y root-repo
> pkg install -y tshark
> ```
> Or install Termux:API for additional capabilities:
> ```bash
> pkg install -y termux-api
> ```

---

## Step 3 — Get NetWatch

```bash
# Option A: Unzip the downloaded zip
cd ~
unzip ~/storage/downloads/NetWatch-v2_0.zip
cd NetWatch-v2_0

# Option B: Clone from git (if hosted)
# git clone https://github.com/yourrepo/NetWatch.git
# cd NetWatch
```

---

## Step 4 — Install Python Packages

```bash
pip install flask flask-socketio flask-cors \
            scapy python-nmap sqlalchemy \
            paramiko pyyaml apscheduler \
            rich click psutil requests \
            pandas tabulate netifaces netaddr
```

> **Low-storage device?** Install minimal set:
> ```bash
> pip install flask flask-socketio flask-cors sqlalchemy \
>             pyyaml rich psutil requests python-nmap
> ```
> Then run with `python netwatch.py --no-traffic` for reduced deps.

---

## Step 5 — Configure

```bash
cp configs/config.example.yaml configs/config.yaml
nano configs/config.yaml
```

**Find your Wi-Fi interface name:**
```bash
ip link show
# Look for: wlan0, wlan1, rmnet_data0, etc.
```

**Find your network subnet:**
```bash
ip addr show wlan0
# Example output: inet 192.168.1.105/24
# Your subnet = 192.168.1.0/24
```

**Minimum config settings to edit:**
```yaml
network:
  interface: "wlan0"          # Replace with your interface
  subnet: "192.168.1.0/24"   # Replace with your subnet
  gateway: "192.168.1.1"     # Replace with your router IP
```

**Termux recommended settings:**
```yaml
performance:
  low_power_mode: true        # Reduce CPU/RAM usage

discovery:
  interval: 120               # Scan every 2 minutes (saves battery)
  fast_interval: 30           # Quick ARP poll every 30s
  os_fingerprint: false       # Skip OS detection (faster)

traffic:
  enabled: true               # tshark/tcpdump auto-selected

dashboard:
  host: "0.0.0.0"            # Access from any device on your network
  port: 8080
```

---

## Step 6 — Run NetWatch

```bash
# Check all dependencies first
python netwatch.py --check

# Run (no sudo needed on Termux)
python netwatch.py

# Run with LAN dashboard access (access from any phone/PC on your network)
python netwatch.py --host 0.0.0.0

# Run without packet capture (if permission issues)
python netwatch.py --no-traffic

# Run without DNS sniff
python netwatch.py --no-dns

# Quick device scan and exit
python netwatch.py --scan-once
```

**Open the dashboard** in your Android browser or any device on your network:
```
http://127.0.0.1:8080          (from the same phone)
http://192.168.1.105:8080      (from any device — use your phone's IP)
```

---

## Step 7 — Keep Running in Background

### Option A: tmux (recommended)
```bash
pkg install tmux
tmux new -s netwatch
python netwatch.py

# Detach (leave running): Ctrl+B, then D
# Reattach later: tmux attach -t netwatch
# Kill session: tmux kill-session -t netwatch
```

### Option B: Wake lock (prevent Android from killing Termux)
```bash
# In a separate Termux window:
termux-wake-lock
# Then run NetWatch in the main window
```

### Option C: Termux:Boot (start on boot — requires Termux:Boot app)
```bash
pkg install termux-boot
mkdir -p ~/.termux/boot/
cat > ~/.termux/boot/netwatch.sh << 'EOF'
#!/data/data/com.termux/files/usr/bin/sh
cd ~/NetWatch-v2_0
termux-wake-lock
python netwatch.py >> data/boot.log 2>&1
EOF
chmod +x ~/.termux/boot/netwatch.sh
```

---

## Troubleshooting

### "Permission denied" on packet capture
```bash
# Run without capture and use dashboard for device discovery only
python netwatch.py --no-traffic --no-dns
```

### "Interface not found"
```bash
# List all interfaces
ip link show
# Try common Termux interface names:
# wlan0, wlan1, swlan0, rmnet_data0
```

### "nmap not found"
```bash
pkg install nmap
# If still missing:
apt-get install nmap
```

### "No devices found"
```bash
# Trigger ARP traffic first
ping -c 3 192.168.1.1

# Check /proc/net/arp has entries
cat /proc/net/arp

# Try scan-once to debug
python netwatch.py --scan-once
```

### Dashboard unreachable from other devices
```bash
# Make sure host is 0.0.0.0 in config, then find your phone's IP:
ip addr show wlan0
# Access: http://<your-phone-ip>:8080
```

### High battery drain
```yaml
# In config.yaml:
performance:
  low_power_mode: true
discovery:
  interval: 300         # Scan every 5 minutes
  fast_interval: 60     # Quick poll every minute
traffic:
  bw_sample_interval: 30
```

---

## Security on Termux

The dashboard binds to `127.0.0.1` by default (localhost only).
To allow access from your other devices while keeping it reasonably secure:

```yaml
dashboard:
  host: "0.0.0.0"
  auth_enabled: true
  username: "admin"
  password: "YourStrongPassword123"
  secret_key: "generate with: python -c \"import secrets; print(secrets.token_hex(32))\""
```

---

## Tested Android Versions

| Android | Termux Version | Status |
|---------|---------------|--------|
| Android 10+ | F-Droid latest | ✅ Fully working |
| Android 8–9 | F-Droid latest | ✅ Working (may need root for capture) |
| Android 7 | F-Droid 0.118.x | ⚠️ Limited (Python 3.10 max) |

---

## Uninstall

```bash
rm -rf ~/NetWatch-v2_0
pip uninstall flask flask-socketio flask-cors scapy sqlalchemy \
               python-nmap paramiko pyyaml apscheduler rich psutil \
               requests pandas tabulate netifaces netaddr
```

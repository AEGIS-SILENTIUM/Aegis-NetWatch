# Installation on Android (Termux)

> ⚠️ **DISCLAIMER**: NetWatch is for authorized use on networks and devices you own only.
> Unauthorized network monitoring is illegal under Philippine law (RA 10175) and internationally.

---

## Step 1 — Install Termux packages

Open Termux and run:

```bash
pkg update && pkg upgrade -y
pkg install -y python nmap tshark arp-scan
```

> If tshark or arp-scan aren't available in your Termux repo, install via:
> ```bash
> pkg install -y wireshark
> ```

---

## Step 2 — Install Python packages

```bash
pip install flask flask-socketio flask-cors scapy python-nmap \
            sqlalchemy apscheduler paramiko pyyaml \
            netifaces netaddr pyshark pandas tabulate \
            rich click psutil requests
```

---

## Step 3 — Configure

```bash
cd NetWatch
cp configs/config.example.yaml configs/config.yaml
nano configs/config.yaml
```

Find your Wi-Fi interface name:
```bash
ip link show
# Look for wlan0 or similar
```

Find your subnet:
```bash
ip addr show wlan0
# e.g. 192.168.1.100/24 → subnet is 192.168.1.0/24
```

---

## Step 4 — Run (NO sudo needed on Termux)

```bash
python netwatch.py --check   # verify dependencies
python netwatch.py           # run it
```

Open the dashboard in your Android browser:
```
http://127.0.0.1:8080
```

---

## Notes for Termux

- **No sudo needed** — Termux runs as user, already has access to your Wi-Fi interface
- **Packet capture** may require `termux-setup-storage` and root if you want full pcap
- **Without root**: Discovery (ARP/Nmap) and DNS logging still work fully
- **With root** (rooted device): Full packet capture works via tshark
- If `arp-scan` isn't available: scanner falls back to `nmap -sn` automatically
- Run `termux-wake-lock` to prevent Android killing the process in background

---

## Termux Background Running

To keep NetWatch running when you switch apps:
```bash
termux-wake-lock
python netwatch.py
```

Or use tmux:
```bash
pkg install tmux
tmux new -s netwatch
python netwatch.py
# Detach: Ctrl+B then D
# Reattach: tmux attach -t netwatch
```

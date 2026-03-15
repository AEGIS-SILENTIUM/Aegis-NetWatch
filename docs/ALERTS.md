# Alert Rules Reference

> ⚠️ **DISCLAIMER**: Alert rules apply only to your own network.

---

## Built-in Alert Rules

### new_device
Fires when a device with an unknown MAC address joins your network.
- **Severity**: MEDIUM
- **Use**: Detect unauthorized devices connecting to your Wi-Fi

### port_scan
Fires when a device contacts 15+ distinct ports within 10 seconds.
- **Severity**: HIGH
- **Use**: Detect reconnaissance activity from a device on your network

### bandwidth_spike
Fires when a device exceeds the configured Mbps threshold in a 10-second window.
- **Severity**: MEDIUM
- **Configurable**: `alerts.bandwidth_spike_mbps`

### dns_anomaly
Fires when a device queries a domain matching suspicious patterns (known malware TLDs, DGA patterns).
- **Severity**: HIGH

### insecure_protocol
Fires when Telnet (port 23) traffic is detected.
- **Severity**: MEDIUM
- **Use**: Identify devices using unencrypted protocols

---

## Webhook Integration

Set `alerts.webhook_url` to receive alerts as HTTP POST:
```json
{
  "id": 42,
  "severity": "HIGH",
  "category": "port_scan",
  "title": "Possible port scan from 192.168.1.5",
  "description": "Device 192.168.1.5 hit 22 distinct ports in 10 seconds.",
  "device_ip": "192.168.1.5",
  "timestamp": "2026-03-14T10:30:00"
}
```

Compatible with Slack incoming webhooks, Discord webhooks, and any HTTP endpoint.

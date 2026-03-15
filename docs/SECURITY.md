# Security Hardening Guide

> ⚠️ **DISCLAIMER**: NetWatch is for authorized monitoring of your own network only.

---

## Dashboard Security

### 1. Enable Authentication
```yaml
dashboard:
  auth_enabled: true
  username: "admin"
  password: "YOUR_STRONG_PASSWORD_HERE"
  secret_key: "RANDOM_32_CHAR_STRING_HERE"
```

Generate a strong secret key:
```bash
python3 -c "import secrets; print(secrets.token_hex(32))"
```

### 2. Restrict to Localhost
```yaml
dashboard:
  host: "127.0.0.1"   # Only local machine can access
```

Only expose to LAN (`0.0.0.0`) if you trust all devices on your network.

### 3. Use a Reverse Proxy with TLS (Production)
Put Nginx in front with HTTPS:
```nginx
server {
    listen 443 ssl;
    ssl_certificate     /etc/ssl/certs/netwatch.crt;
    ssl_certificate_key /etc/ssl/private/netwatch.key;
    location / { proxy_pass http://127.0.0.1:8080; }
}
```

---

## Database Security
- `data/netwatch.db` contains sensitive network data
- Set permissions: `chmod 600 data/netwatch.db`
- Back up regularly: `cp data/netwatch.db backups/`
- The database is not encrypted at rest — store on an encrypted volume if needed

---

## Network Considerations
- NetWatch requires a promiscuous-mode interface for full traffic capture
- All data is stored locally — nothing is sent to external servers
- Logs are at `data/netwatch.log` — rotate with logrotate if needed

---

## Privacy
- DNS queries and traffic flows of all devices on your network are logged
- Inform household members that monitoring is in place
- Comply with your local data protection laws (GDPR, Data Privacy Act, etc.)

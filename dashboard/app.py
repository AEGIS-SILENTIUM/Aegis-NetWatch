"""
NetWatch — Web Dashboard
Flask application providing REST API + live WebSocket dashboard.
All data is from your own network only.

DISCLAIMER: Use only on networks/devices you own or are authorized to monitor.
"""
import logging
import os
from datetime import datetime
from functools import wraps
from typing import Optional

from flask import Flask, render_template, jsonify, request, session, redirect, url_for
from flask_socketio import SocketIO, emit
from flask_cors import CORS

log = logging.getLogger("netwatch.dashboard")

app = Flask(__name__, template_folder="templates", static_folder="static")
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# These are injected at startup by NetWatchEngine
_db  = None
_bus = None
_cfg = None


def init_dashboard(db, bus, config: dict):
    """Called by netwatch.py to inject dependencies."""
    global _db, _bus, _cfg
    _db  = db
    _bus = bus
    _cfg = config

    dc = config.get("dashboard", {})
    app.secret_key = dc.get("secret_key", os.urandom(32))

    # Subscribe to events and forward to WebSocket clients
    bus.subscribe("device.discovered",   lambda d: _ws_emit("device_event",   d))
    bus.subscribe("device.updated",      lambda d: _ws_emit("device_event",   d))
    bus.subscribe("flow.captured",       lambda d: _ws_emit("flow_event",     d))
    bus.subscribe("dns.query",           lambda d: _ws_emit("dns_event",      d))
    bus.subscribe("alert.fired",         lambda d: _ws_emit("alert_event",    d))
    bus.subscribe("bandwidth.sample",    lambda d: _ws_emit("bandwidth_event", d))
    bus.subscribe("scan.complete",       lambda d: _ws_emit("scan_complete",  d))


def _ws_emit(event: str, data):
    """Safely emit WebSocket event to all connected clients."""
    try:
        socketio.emit(event, data)
    except Exception as e:
        log.debug("WS emit error: %s", e)


# ── Auth ──────────────────────────────────────────────────────

def _auth_enabled() -> bool:
    return _cfg and _cfg.get("dashboard", {}).get("auth_enabled", False)


def _login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if _auth_enabled() and not session.get("authenticated"):
            if request.is_json:
                return jsonify({"error": "Unauthorized"}), 401
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        dc   = _cfg.get("dashboard", {})
        user = request.form.get("username")
        pw   = request.form.get("password")
        if user == dc.get("username") and pw == dc.get("password"):
            session["authenticated"] = True
            return redirect(url_for("index"))
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ── Pages ─────────────────────────────────────────────────────

@app.route("/")
@_login_required
def index():
    return render_template("index.html")


@app.route("/devices")
@_login_required
def devices_page():
    return render_template("devices.html")


@app.route("/traffic")
@_login_required
def traffic_page():
    return render_template("traffic.html")


@app.route("/dns")
@_login_required
def dns_page():
    return render_template("dns.html")


@app.route("/alerts")
@_login_required
def alerts_page():
    return render_template("alerts.html")


@app.route("/collector")
@_login_required
def collector_page():
    return render_template("collector.html")


# ── REST API ──────────────────────────────────────────────────

def _err(msg: str, status: int = 400):
    return jsonify({"error": msg}), status


@app.route("/api/status")
@_login_required
def api_status():
    stats = _db.get_stats() if _db else {}
    return jsonify({
        "status":    "running",
        "timestamp": datetime.utcnow().isoformat(),
        "stats":     stats,
        "version":   "1.0.0",
    })


@app.route("/api/devices")
@_login_required
def api_devices():
    devs = _db.get_all_devices()
    return jsonify({"devices": [d.to_dict() for d in devs], "count": len(devs)})


@app.route("/api/devices/active")
@_login_required
def api_devices_active():
    devs = _db.get_active_devices()
    return jsonify({"devices": [d.to_dict() for d in devs], "count": len(devs)})


@app.route("/api/devices/<int:device_id>")
@_login_required
def api_device_detail(device_id: int):
    with _db.Session() as s:
        from core.database import Device
        dev = s.query(Device).filter_by(id=device_id).first()
        if not dev:
            return _err("Device not found", 404)
        d = dev.to_dict()
    d["flows"]      = [f.to_dict() for f in _db.get_flows_by_ip(d["ip"], limit=50)]
    d["dns_queries"] = [q.to_dict() for q in _db.get_dns_by_device(d["ip"], limit=50)]
    d["bandwidth"]  = [b.to_dict() for b in _db.get_bandwidth_history(d["ip"], hours=1)]
    return jsonify(d)


@app.route("/api/devices/<int:device_id>/tag", methods=["POST"])
@_login_required
def api_device_tag(device_id: int):
    tag = request.json.get("tag", "").strip()
    if not tag:
        return _err("tag required")
    with _db.Session() as s:
        from core.database import Device
        dev = s.query(Device).filter_by(id=device_id).first()
        if not dev:
            return _err("Device not found", 404)
        tags = dev.tags or []
        if tag not in tags:
            tags.append(tag)
        dev.tags = tags
        s.commit()
    return jsonify({"ok": True})


@app.route("/api/devices/<int:device_id>/note", methods=["POST"])
@_login_required
def api_device_note(device_id: int):
    note = request.json.get("note", "").strip()
    with _db.Session() as s:
        from core.database import Device
        dev = s.query(Device).filter_by(id=device_id).first()
        if not dev:
            return _err("Device not found", 404)
        dev.notes = note
        s.commit()
    return jsonify({"ok": True})


@app.route("/api/traffic/flows")
@_login_required
def api_flows():
    minutes = int(request.args.get("minutes", 5))
    limit   = int(request.args.get("limit", 200))
    flows   = _db.get_recent_flows(minutes=minutes, limit=limit)
    return jsonify({"flows": [f.to_dict() for f in flows], "count": len(flows)})


@app.route("/api/traffic/top-talkers")
@_login_required
def api_top_talkers():
    # Calculate from recent flows
    from collections import defaultdict
    flows  = _db.get_recent_flows(minutes=5, limit=5000)
    counts = defaultdict(int)
    for f in flows:
        counts[f.src_ip] += f.bytes_sent
    sorted_items = sorted(counts.items(), key=lambda x: x[1], reverse=True)[:10]
    return jsonify({"top_talkers": [{"ip": ip, "bytes": b} for ip, b in sorted_items]})


@app.route("/api/traffic/protocols")
@_login_required
def api_protocols():
    from collections import defaultdict
    minutes = int(request.args.get("minutes", 5))
    flows   = _db.get_recent_flows(minutes=minutes, limit=5000)
    breakdown = defaultdict(int)
    for f in flows:
        breakdown[f.protocol or "Other"] += f.bytes_sent
    return jsonify({"protocols": dict(breakdown)})


@app.route("/api/dns")
@_login_required
def api_dns():
    minutes = int(request.args.get("minutes", 60))
    limit   = int(request.args.get("limit", 500))
    queries = _db.get_recent_dns(minutes=minutes, limit=limit)
    return jsonify({"queries": [q.to_dict() for q in queries], "count": len(queries)})


@app.route("/api/dns/top-domains")
@_login_required
def api_top_domains():
    from collections import Counter
    queries = _db.get_recent_dns(minutes=60, limit=5000)
    counts  = Counter(q.domain for q in queries)
    top     = [{"domain": d, "count": c} for d, c in counts.most_common(20)]
    return jsonify({"top_domains": top})


@app.route("/api/dns/flagged")
@_login_required
def api_flagged_dns():
    with _db.Session() as s:
        from core.database import DnsQuery
        flagged = s.query(DnsQuery).filter_by(flagged=True).order_by(
            DnsQuery.timestamp.desc()).limit(100).all()
    return jsonify({"flagged": [q.to_dict() for q in flagged]})


@app.route("/api/alerts")
@_login_required
def api_alerts():
    limit      = int(request.args.get("limit", 100))
    unacked    = request.args.get("unacked", "false").lower() == "true"
    alerts     = _db.get_alerts(limit=limit, unacked_only=unacked)
    return jsonify({"alerts": [a.to_dict() for a in alerts], "count": len(alerts)})


@app.route("/api/alerts/<int:alert_id>/acknowledge", methods=["POST"])
@_login_required
def api_ack_alert(alert_id: int):
    ok = _db.acknowledge_alert(alert_id)
    if ok:
        return jsonify({"ok": True})
    return _err("Alert not found", 404)


@app.route("/api/bandwidth/<path:device_ip>")
@_login_required
def api_bandwidth(device_ip: str):
    hours   = int(request.args.get("hours", 1))
    samples = _db.get_bandwidth_history(device_ip, hours=hours)
    return jsonify({"bandwidth": [s.to_dict() for s in samples]})


@app.route("/api/collector/files")
@_login_required
def api_collected_files():
    files = _db.get_collected_files(limit=100)
    return jsonify({"files": [f.to_dict() for f in files]})


@app.route("/api/export/devices")
@_login_required
def api_export_devices():
    """Export all device data as JSON."""
    devs = _db.get_all_devices()
    return jsonify({
        "exported_at": datetime.utcnow().isoformat(),
        "devices":     [d.to_dict() for d in devs],
    })


@app.route("/api/export/dns")
@_login_required
def api_export_dns():
    """Export DNS query history."""
    queries = _db.get_recent_dns(minutes=60*24*7, limit=50000)
    return jsonify({
        "exported_at": datetime.utcnow().isoformat(),
        "queries":     [q.to_dict() for q in queries],
    })


# ── WebSocket ─────────────────────────────────────────────────

@socketio.on("connect")
def ws_connect():
    log.debug("Dashboard client connected: %s", request.sid)
    if _db:
        emit("init_data", {
            "devices": [d.to_dict() for d in _db.get_active_devices()],
            "alerts":  [a.to_dict() for a in _db.get_alerts(limit=20, unacked_only=True)],
            "stats":   _db.get_stats(),
        })


@socketio.on("disconnect")
def ws_disconnect():
    log.debug("Dashboard client disconnected: %s", request.sid)


def run_dashboard(db, bus, config: dict):
    """Start the Flask dashboard server."""
    init_dashboard(db, bus, config)
    dc = config.get("dashboard", {})
    host = dc.get("host", "127.0.0.1")
    port = dc.get("port", 8080)
    log.info("Dashboard starting at http://%s:%d", host, port)
    socketio.run(app, host=host, port=port, debug=False, use_reloader=False, log_output=False)

"""
HIDENTIFY - Network Intrusion Detection & Monitoring System
Main application entry point.

Run with elevated privileges (packet capture requires it):
    Linux/macOS:  sudo python3 app.py
    Windows:      run cmd/PowerShell "as Administrator", then: python app.py
"""

import functools
import os
import sys
import time

from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_socketio import SocketIO
from werkzeug.security import check_password_hash

import config
from core.database import Database
from core.geoip import GeoIP
from core.blocklist import BlocklistManager
from core.alerts import AlertManager
from core.detectors import DetectionEngine
from core.anomaly import TrafficAggregator
from core.sniffer import SnifferEngine

# When bundled with PyInstaller, templates/static are extracted to a temp
# folder pointed to by sys._MEIPASS instead of living next to this file.
if getattr(sys, "frozen", False):
    _RESOURCE_DIR = sys._MEIPASS
else:
    _RESOURCE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(_RESOURCE_DIR, "templates"),
    static_folder=os.path.join(_RESOURCE_DIR, "static"),
)
app.config["SECRET_KEY"] = config.SECRET_KEY
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# ---------------- Core services ----------------
settings = config.load_settings()
db = Database(config.DB_PATH)
geoip = GeoIP(config.GEOIP_DB_PATH)
blocklist_manager = BlocklistManager(db)
alert_manager = AlertManager(db, socketio, geoip, blocklist_manager, settings_provider=lambda: settings)
detection_engine = DetectionEngine(settings, alert_manager, blocklist_manager)
aggregator = TrafficAggregator(settings, db, alert_manager, socketio)


def on_packet(pkt):
    detection_engine.process(pkt)
    aggregator.ingest(pkt)


sniffer = SnifferEngine(on_packet)

app_state = {"capturing": False, "interface": settings.get("interface"), "started_at": None}


# ---------------- Auth ----------------
def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        if username == config.DEFAULT_ADMIN_USER and check_password_hash(config.DEFAULT_ADMIN_PASSWORD_HASH, password):
            session["logged_in"] = True
            session["username"] = username
            return redirect(url_for("dashboard"))
        error = "Invalid username or password."
    return render_template("login.html", error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------- Pages ----------------
@app.route("/")
@login_required
def dashboard():
    return render_template("dashboard.html", username=session.get("username"))


@app.route("/traffic")
@login_required
def traffic_page():
    return render_template("traffic.html", username=session.get("username"))


@app.route("/alerts")
@login_required
def alerts_page():
    return render_template("alerts.html", username=session.get("username"))


@app.route("/blocklist")
@login_required
def blocklist_page():
    return render_template("blocklist.html", username=session.get("username"))


@app.route("/settings")
@login_required
def settings_page():
    return render_template("settings.html", username=session.get("username"), settings=settings)


# ---------------- API: capture control ----------------
@app.route("/api/interfaces")
@login_required
def api_interfaces():
    return jsonify({
        "interfaces": SnifferEngine.list_interfaces(),
        "scapy_available": SnifferEngine.scapy_available(),
    })


@app.route("/api/capture/start", methods=["POST"])
@login_required
def api_capture_start():
    iface = request.json.get("interface") if request.is_json else None
    ok = sniffer.start(iface=iface)
    if ok:
        app_state["capturing"] = True
        app_state["interface"] = iface
        app_state["started_at"] = time.time()
        if not aggregator._thread.is_alive():
            aggregator.start()
    return jsonify({"success": ok, "error": sniffer.last_error})


@app.route("/api/capture/stop", methods=["POST"])
@login_required
def api_capture_stop():
    sniffer.stop()
    app_state["capturing"] = False
    return jsonify({"success": True})


@app.route("/api/status")
@login_required
def api_status():
    return jsonify({
        "capturing": sniffer.is_running(),
        "interface": app_state["interface"],
        "started_at": app_state["started_at"],
        "total_alerts": db.count_alerts(),
        "blocked_ips": len(db.get_blocklist()),
    })


# ---------------- API: alerts ----------------
@app.route("/api/alerts")
@login_required
def api_alerts():
    severity = request.args.get("severity") or None
    alert_type = request.args.get("type") or None
    limit = int(request.args.get("limit", 200))
    return jsonify(db.get_alerts(limit=limit, severity=severity, alert_type=alert_type))


@app.route("/api/alerts/<int:alert_id>/resolve", methods=["POST"])
@login_required
def api_resolve_alert(alert_id):
    db.resolve_alert(alert_id)
    return jsonify({"success": True})


@app.route("/api/stats")
@login_required
def api_stats():
    return jsonify(db.get_recent_stats(limit=int(request.args.get("limit", 60))))


# ---------------- API: blocklist ----------------
@app.route("/api/blocklist")
@login_required
def api_blocklist_get():
    return jsonify(db.get_blocklist())


@app.route("/api/blocklist/add", methods=["POST"])
@login_required
def api_blocklist_add():
    data = request.json
    ip = data.get("ip", "").strip()
    reason = data.get("reason", "Manually blocked")
    if not ip:
        return jsonify({"success": False, "error": "IP required"}), 400
    enforced = blocklist_manager.block_ip(ip, reason)
    socketio.emit("blocklist_update", db.get_blocklist())
    return jsonify({"success": True, "enforced": enforced})


@app.route("/api/blocklist/remove", methods=["POST"])
@login_required
def api_blocklist_remove():
    ip = request.json.get("ip", "").strip()
    blocklist_manager.unblock_ip(ip)
    socketio.emit("blocklist_update", db.get_blocklist())
    return jsonify({"success": True})


# ---------------- API: settings ----------------
@app.route("/api/settings", methods=["GET", "POST"])
@login_required
def api_settings():
    global settings
    if request.method == "POST":
        incoming = request.json or {}
        settings.update(incoming)
        config.save_settings(settings)
        detection_engine.reload(settings, blocklist_manager)
        return jsonify({"success": True, "settings": settings})
    return jsonify(settings)


if __name__ == "__main__":
    print("=" * 60)
    print("  HIDENTIFY - Network Intrusion Detection System")
    print("  Default login -> username: admin | password: hidentify123")
    print("  CHANGE THE DEFAULT PASSWORD before real deployment!")
    print("=" * 60)
    socketio.run(app, host="0.0.0.0", port=5000, debug=False, allow_unsafe_werkzeug=True)

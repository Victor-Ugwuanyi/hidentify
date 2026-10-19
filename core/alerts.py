"""
HIDENTIFY - Alert Manager
Central point through which every detector raises an alert.
Handles de-duplication (cooldown), persistence, GeoIP enrichment,
optional auto-blocking, and pushing live events to the frontend via SocketIO.
"""

import time
import threading


class AlertManager:
    def __init__(self, db, socketio, geoip, blocklist_manager, settings_provider):
        self.db = db
        self.socketio = socketio
        self.geoip = geoip
        self.blocklist_manager = blocklist_manager
        self.settings_provider = settings_provider
        self._cooldowns = {}  # (type, src_ip) -> last_ts
        self._lock = threading.Lock()
        self.cooldown_seconds = 8  # avoid spamming identical alerts

    def raise_alert(self, alert_type, severity, src_ip=None, dst_ip=None, description=""):
        key = (alert_type, src_ip)
        now = time.time()
        with self._lock:
            last = self._cooldowns.get(key, 0)
            if now - last < self.cooldown_seconds:
                return None
            self._cooldowns[key] = now

        country, city = (None, None)
        settings = self.settings_provider()
        if settings.get("geoip_enabled") and src_ip:
            country, city = self.geoip.lookup(src_ip)

        record = self.db.add_alert(alert_type, severity, src_ip, dst_ip, description, country, city)

        if self.socketio:
            self.socketio.emit("new_alert", record)

        if severity == "critical" and settings.get("auto_block_critical") and src_ip:
            self.blocklist_manager.block_ip(src_ip, reason=f"Auto-blocked: {alert_type}")
            if self.socketio:
                self.socketio.emit("blocklist_update", self.db.get_blocklist())

        return record

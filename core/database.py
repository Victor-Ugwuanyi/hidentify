"""
HIDENTIFY - Database layer
Lightweight SQLite wrapper (no ORM) for alerts, blocklist entries,
and rolling traffic statistics.
"""

import sqlite3
import threading
from datetime import datetime

_lock = threading.Lock()


class Database:
    def __init__(self, db_path):
        self.db_path = db_path
        self._init_schema()

    def _conn(self):
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self):
        with _lock, self._conn() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    src_ip TEXT,
                    dst_ip TEXT,
                    description TEXT,
                    country TEXT,
                    city TEXT,
                    resolved INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS blocklist (
                    ip TEXT PRIMARY KEY,
                    reason TEXT,
                    added_at TEXT,
                    enforced INTEGER DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS traffic_stats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    packet_count INTEGER,
                    byte_count INTEGER,
                    tcp_count INTEGER,
                    udp_count INTEGER,
                    icmp_count INTEGER,
                    other_count INTEGER,
                    unique_src INTEGER,
                    anomaly_score REAL
                );

                CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);
                CREATE INDEX IF NOT EXISTS idx_stats_ts ON traffic_stats(timestamp);
                """
            )

    # ---------------- Alerts ----------------
    def add_alert(self, alert_type, severity, src_ip, dst_ip, description, country=None, city=None):
        ts = datetime.utcnow().isoformat()
        with _lock, self._conn() as conn:
            cur = conn.execute(
                """INSERT INTO alerts (timestamp, type, severity, src_ip, dst_ip, description, country, city)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (ts, alert_type, severity, src_ip, dst_ip, description, country, city),
            )
            return {
                "id": cur.lastrowid, "timestamp": ts, "type": alert_type, "severity": severity,
                "src_ip": src_ip, "dst_ip": dst_ip, "description": description,
                "country": country, "city": city, "resolved": 0,
            }

    def get_alerts(self, limit=200, severity=None, alert_type=None):
        query = "SELECT * FROM alerts"
        clauses, params = [], []
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if alert_type:
            clauses.append("type = ?")
            params.append(alert_type)
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        with self._conn() as conn:
            rows = conn.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    def count_alerts(self, since_iso=None):
        with self._conn() as conn:
            if since_iso:
                r = conn.execute("SELECT COUNT(*) c FROM alerts WHERE timestamp >= ?", (since_iso,)).fetchone()
            else:
                r = conn.execute("SELECT COUNT(*) c FROM alerts").fetchone()
            return r["c"]

    def resolve_alert(self, alert_id):
        with _lock, self._conn() as conn:
            conn.execute("UPDATE alerts SET resolved = 1 WHERE id = ?", (alert_id,))

    # ---------------- Blocklist ----------------
    def add_block(self, ip, reason, enforced=False):
        ts = datetime.utcnow().isoformat()
        with _lock, self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO blocklist (ip, reason, added_at, enforced) VALUES (?, ?, ?, ?)",
                (ip, reason, ts, int(enforced)),
            )

    def remove_block(self, ip):
        with _lock, self._conn() as conn:
            conn.execute("DELETE FROM blocklist WHERE ip = ?", (ip,))

    def is_blocked(self, ip):
        with self._conn() as conn:
            r = conn.execute("SELECT 1 FROM blocklist WHERE ip = ?", (ip,)).fetchone()
            return r is not None

    def get_blocklist(self):
        with self._conn() as conn:
            rows = conn.execute("SELECT * FROM blocklist ORDER BY added_at DESC").fetchall()
            return [dict(r) for r in rows]

    # ---------------- Traffic stats ----------------
    def add_stats_bucket(self, packet_count, byte_count, tcp_count, udp_count,
                          icmp_count, other_count, unique_src, anomaly_score=None):
        ts = datetime.utcnow().isoformat()
        with _lock, self._conn() as conn:
            conn.execute(
                """INSERT INTO traffic_stats
                   (timestamp, packet_count, byte_count, tcp_count, udp_count, icmp_count, other_count, unique_src, anomaly_score)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (ts, packet_count, byte_count, tcp_count, udp_count, icmp_count, other_count, unique_src, anomaly_score),
            )

    def get_recent_stats(self, limit=60):
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM traffic_stats ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows][::-1]

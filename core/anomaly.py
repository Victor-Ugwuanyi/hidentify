"""
HIDENTIFY - Traffic Aggregator & Anomaly Detection
Buckets raw packets into fixed-size time windows (e.g. 5s), turns each
bucket into a small feature vector, and scores it with an IsolationForest
trained on-the-fly from the first N buckets (an unsupervised "learn what
normal looks like on THIS network" baseline). This is intentionally
lightweight so it works without any labeled attack data.
"""

import time
import threading
import numpy as np

try:
    from sklearn.ensemble import IsolationForest
    _SKLEARN_AVAILABLE = True
except ImportError:
    _SKLEARN_AVAILABLE = False


class TrafficAggregator:
    def __init__(self, settings, db, alert_manager, socketio):
        self.settings = settings
        self.db = db
        self.alert_manager = alert_manager
        self.socketio = socketio
        self._lock = threading.Lock()
        self._reset_bucket()
        self.model = None
        self.baseline_features = []
        self.trained = False
        self._stop = False
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def start(self):
        self._stop = False
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop = True

    def _reset_bucket(self):
        self.bucket_start = time.time()
        self.packet_count = 0
        self.byte_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0
        self.other_count = 0
        self.src_ips = set()
        self.dst_ports = set()

    def ingest(self, pkt):
        with self._lock:
            self.packet_count += 1
            self.byte_count += pkt.get("size", 0)
            proto = pkt.get("proto")
            if proto == "TCP":
                self.tcp_count += 1
            elif proto == "UDP":
                self.udp_count += 1
            elif proto == "ICMP":
                self.icmp_count += 1
            else:
                self.other_count += 1
            if pkt.get("src"):
                self.src_ips.add(pkt["src"])
            if pkt.get("dport"):
                self.dst_ports.add(pkt["dport"])

    def _feature_vector(self, snapshot):
        total = max(snapshot["packet_count"], 1)
        return [
            snapshot["packet_count"],
            snapshot["byte_count"],
            snapshot["tcp_count"] / total,
            snapshot["udp_count"] / total,
            snapshot["icmp_count"] / total,
            len(snapshot["src_ips"]),
            len(snapshot["dst_ports"]),
        ]

    def _loop(self):
        window = self.settings.get("anomaly_window_seconds", 5)
        while not self._stop:
            time.sleep(window)
            with self._lock:
                snapshot = {
                    "packet_count": self.packet_count,
                    "byte_count": self.byte_count,
                    "tcp_count": self.tcp_count,
                    "udp_count": self.udp_count,
                    "icmp_count": self.icmp_count,
                    "other_count": self.other_count,
                    "src_ips": set(self.src_ips),
                    "dst_ports": set(self.dst_ports),
                }
                self._reset_bucket()

            score = self._score_and_learn(snapshot)

            self.db.add_stats_bucket(
                snapshot["packet_count"], snapshot["byte_count"], snapshot["tcp_count"],
                snapshot["udp_count"], snapshot["icmp_count"], snapshot["other_count"],
                len(snapshot["src_ips"]), score,
            )

            if self.socketio:
                self.socketio.emit("traffic_update", {
                    "timestamp": time.time(),
                    "packet_count": snapshot["packet_count"],
                    "byte_count": snapshot["byte_count"],
                    "tcp_count": snapshot["tcp_count"],
                    "udp_count": snapshot["udp_count"],
                    "icmp_count": snapshot["icmp_count"],
                    "other_count": snapshot["other_count"],
                    "unique_src": len(snapshot["src_ips"]),
                    "anomaly_score": score,
                })

    def _score_and_learn(self, snapshot):
        if not self.settings.get("anomaly_detection_enabled", True) or not _SKLEARN_AVAILABLE:
            return None

        features = self._feature_vector(snapshot)

        if not self.trained:
            self.baseline_features.append(features)
            needed = self.settings.get("anomaly_baseline_buckets", 24)
            if len(self.baseline_features) >= needed:
                self.model = IsolationForest(
                    contamination=self.settings.get("anomaly_contamination", 0.05),
                    random_state=42,
                )
                self.model.fit(np.array(self.baseline_features))
                self.trained = True
            return None  # no score yet while establishing baseline

        score = self.model.decision_function([features])[0]  # higher = more normal
        is_anomaly = self.model.predict([features])[0] == -1

        if is_anomaly and self.alert_manager:
            self.alert_manager.raise_alert(
                "Traffic Anomaly",
                "medium",
                src_ip=None,
                dst_ip=None,
                description=(
                    f"Unusual traffic pattern detected: {snapshot['packet_count']} packets, "
                    f"{len(snapshot['src_ips'])} unique sources in this window "
                    f"(anomaly score {score:.3f})."
                ),
            )
        return float(score)

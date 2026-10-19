"""
HIDENTIFY - Detection Engine
Signature/threshold-based detectors, each maintaining its own small
sliding-window state. Cheap by design so they can run on every packet
in real time without a database round-trip.
"""

import time
from collections import defaultdict, deque


class SlidingWindowCounter:
    """Tracks timestamped events per key, evicting anything outside `window` seconds."""

    def __init__(self, window):
        self.window = window
        self.events = defaultdict(deque)

    def add(self, key, ts=None):
        ts = ts or time.time()
        dq = self.events[key]
        dq.append(ts)
        self._evict(dq, ts)
        return len(dq)

    def _evict(self, dq, now):
        while dq and now - dq[0] > self.window:
            dq.popleft()


class PortScanDetector:
    """Flags a source IP that touches many distinct destination ports quickly."""

    def __init__(self, threshold, window, alert_cb):
        self.threshold = threshold
        self.window = window
        self.alert_cb = alert_cb
        self.port_sets = defaultdict(lambda: deque())  # src -> deque[(ts, port)]

    def process(self, pkt):
        if pkt["proto"] not in ("TCP", "UDP") or pkt["dport"] is None or pkt["src"] is None:
            return
        now = pkt["ts"]
        dq = self.port_sets[pkt["src"]]
        dq.append((now, pkt["dport"]))
        while dq and now - dq[0][0] > self.window:
            dq.popleft()

        unique_ports = {p for _, p in dq}
        if len(unique_ports) >= self.threshold:
            self.alert_cb(
                "Port Scan",
                "high",
                src_ip=pkt["src"],
                dst_ip=pkt["dst"],
                description=(
                    f"{pkt['src']} probed {len(unique_ports)} distinct ports on "
                    f"{pkt['dst']} within {self.window}s — likely port scan."
                ),
            )


class SynFloodDetector:
    """Flags a source sending an abnormal rate of TCP SYN packets (possible DoS / scan)."""

    def __init__(self, threshold, window, alert_cb):
        self.counter = SlidingWindowCounter(window)
        self.threshold = threshold
        self.window = window
        self.alert_cb = alert_cb

    def process(self, pkt):
        if pkt["proto"] != "TCP" or not pkt.get("flags"):
            return
        if "S" in pkt["flags"] and "A" not in pkt["flags"]:  # SYN, not SYN-ACK
            count = self.counter.add(pkt["src"], pkt["ts"])
            if count >= self.threshold:
                self.alert_cb(
                    "SYN Flood",
                    "critical",
                    src_ip=pkt["src"],
                    dst_ip=pkt["dst"],
                    description=(
                        f"{pkt['src']} sent {count} SYN packets in {self.window}s — "
                        f"possible SYN flood / DoS attempt targeting {pkt['dst']}."
                    ),
                )


class IcmpFloodDetector:
    """Flags a source sending an abnormal rate of ICMP echo requests (ping flood)."""

    def __init__(self, threshold, window, alert_cb):
        self.counter = SlidingWindowCounter(window)
        self.threshold = threshold
        self.window = window
        self.alert_cb = alert_cb

    def process(self, pkt):
        if pkt["proto"] != "ICMP" or pkt.get("icmp_type") != 8:  # echo-request
            return
        count = self.counter.add(pkt["src"], pkt["ts"])
        if count >= self.threshold:
            self.alert_cb(
                "ICMP Flood",
                "high",
                src_ip=pkt["src"],
                dst_ip=pkt["dst"],
                description=f"{pkt['src']} sent {count} ICMP echo requests in {self.window}s — possible ping flood.",
            )


class ArpSpoofDetector:
    """Flags when the same IP is claimed by more than one MAC address (classic ARP spoofing)."""

    def __init__(self, alert_cb):
        self.alert_cb = alert_cb
        self.ip_to_mac = {}

    def process(self, pkt):
        if pkt["proto"] != "ARP" or pkt.get("arp_op") != 2:  # is-at (reply)
            return
        ip, mac = pkt["src"], pkt.get("arp_hwsrc")
        if not ip or not mac:
            return
        known_mac = self.ip_to_mac.get(ip)
        if known_mac and known_mac != mac:
            self.alert_cb(
                "ARP Spoofing",
                "critical",
                src_ip=ip,
                dst_ip=None,
                description=(
                    f"IP {ip} changed MAC from {known_mac} to {mac} — "
                    f"possible ARP spoofing / man-in-the-middle attempt."
                ),
            )
        self.ip_to_mac[ip] = mac


class BlocklistDetector:
    """Flags any traffic to/from an IP already on the blocklist."""

    def __init__(self, blocklist_manager, alert_cb):
        self.blocklist_manager = blocklist_manager
        self.alert_cb = alert_cb

    def process(self, pkt):
        for ip in (pkt.get("src"), pkt.get("dst")):
            if ip and self.blocklist_manager.is_blocked(ip):
                self.alert_cb(
                    "Blocklisted IP Activity",
                    "medium",
                    src_ip=pkt.get("src"),
                    dst_ip=pkt.get("dst"),
                    description=f"Traffic involving blocklisted IP {ip} detected.",
                )
                return


class DetectionEngine:
    """Fan-out: runs every packet through all enabled detectors."""

    def __init__(self, settings, alert_manager, blocklist_manager):
        self.alert_cb = alert_manager.raise_alert
        self.detectors = []
        self.reload(settings, blocklist_manager)

    def reload(self, settings, blocklist_manager):
        self.detectors = [
            PortScanDetector(settings["port_scan_threshold"], settings["port_scan_window"], self.alert_cb),
            SynFloodDetector(settings["syn_flood_threshold"], settings["syn_flood_window"], self.alert_cb),
            IcmpFloodDetector(settings["icmp_flood_threshold"], settings["icmp_flood_window"], self.alert_cb),
            BlocklistDetector(blocklist_manager, self.alert_cb),
        ]
        if settings.get("arp_spoof_enabled", True):
            self.detectors.append(ArpSpoofDetector(self.alert_cb))

    def process(self, pkt):
        for d in self.detectors:
            try:
                d.process(pkt)
            except Exception:
                continue  # one detector failing must never take down the pipeline

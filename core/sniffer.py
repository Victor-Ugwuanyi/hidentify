"""
HIDENTIFY - Packet Sniffer Engine
Wraps scapy's AsyncSniffer. Every captured packet is parsed into a small
plain dict (cheap, no scapy objects kept around) and handed to a callback,
which the main app wires up to the detection engine + stats aggregator.

Requires: root/administrator privileges and Npcap (Windows) or libpcap (Linux/macOS).
"""

import threading
import time

try:
    from scapy.all import AsyncSniffer, IP, TCP, UDP, ICMP, ARP, get_if_list
    _SCAPY_AVAILABLE = True
except Exception:
    _SCAPY_AVAILABLE = False


class SnifferEngine:
    def __init__(self, on_packet):
        """
        on_packet: callback(dict) called for every parsed packet.
        """
        self.on_packet = on_packet
        self._sniffer = None
        self._running = False
        self._lock = threading.Lock()
        self.last_error = None

    @staticmethod
    def scapy_available():
        return _SCAPY_AVAILABLE

    @staticmethod
    def list_interfaces():
        if not _SCAPY_AVAILABLE:
            return []
        try:
            return get_if_list()
        except Exception:
            return []

    def _parse(self, pkt):
        info = {
            "ts": time.time(),
            "size": len(pkt),
            "proto": "OTHER",
            "src": None,
            "dst": None,
            "sport": None,
            "dport": None,
            "flags": None,
        }
        try:
            if pkt.haslayer(ARP):
                arp = pkt[ARP]
                info["proto"] = "ARP"
                info["src"] = arp.psrc
                info["dst"] = arp.pdst
                info["arp_hwsrc"] = arp.hwsrc
                info["arp_op"] = arp.op
                self.on_packet(info)
                return

            if pkt.haslayer(IP):
                ip = pkt[IP]
                info["src"] = ip.src
                info["dst"] = ip.dst

                if pkt.haslayer(TCP):
                    tcp = pkt[TCP]
                    info["proto"] = "TCP"
                    info["sport"] = tcp.sport
                    info["dport"] = tcp.dport
                    info["flags"] = str(tcp.flags)
                elif pkt.haslayer(UDP):
                    udp = pkt[UDP]
                    info["proto"] = "UDP"
                    info["sport"] = udp.sport
                    info["dport"] = udp.dport
                elif pkt.haslayer(ICMP):
                    icmp = pkt[ICMP]
                    info["proto"] = "ICMP"
                    info["icmp_type"] = icmp.type
                else:
                    info["proto"] = "IP_OTHER"

                self.on_packet(info)
        except Exception:
            pass  # never let a malformed packet crash the sniffer

    def start(self, iface=None):
        if not _SCAPY_AVAILABLE:
            self.last_error = "scapy is not installed or npcap/libpcap is missing."
            return False
        with self._lock:
            if self._running:
                return True
            try:
                self._sniffer = AsyncSniffer(iface=iface, prn=self._parse, store=False)
                self._sniffer.start()
                self._running = True
                self.last_error = None
                return True
            except PermissionError:
                self.last_error = "Permission denied. Run HIDENTIFY as root/administrator."
                return False
            except Exception as e:
                self.last_error = str(e)
                return False

    def stop(self):
        with self._lock:
            if self._sniffer and self._running:
                try:
                    self._sniffer.stop()
                except Exception:
                    pass
                self._running = False

    def is_running(self):
        return self._running

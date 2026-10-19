"""
HIDENTIFY - Blocklist Manager
Keeps the list of blocked IPs in the database and, where possible,
enforces the block at the OS firewall level.

Enforcement is best-effort and platform-specific:
  - Linux:   iptables -A INPUT -s <ip> -j DROP
  - Windows: netsh advfirewall firewall add rule ...
  - macOS:   pf (requires a pre-loaded anchor); enforcement is skipped by
             default and the IP is only tracked/alerted on, since pf setup
             is environment-specific.

If enforcement fails (e.g. not running as admin/root), the IP is still
recorded and shown in the UI as "tracked (not enforced)".
"""

import platform
import subprocess


class BlocklistManager:
    def __init__(self, db):
        self.db = db
        self.system = platform.system()

    def block_ip(self, ip, reason="Manually blocked"):
        enforced = self._enforce_block(ip)
        self.db.add_block(ip, reason, enforced=enforced)
        return enforced

    def unblock_ip(self, ip):
        self._enforce_unblock(ip)
        self.db.remove_block(ip)

    def is_blocked(self, ip):
        return self.db.is_blocked(ip)

    def list_blocked(self):
        return self.db.get_blocklist()

    def _enforce_block(self, ip):
        try:
            if self.system == "Linux":
                subprocess.run(
                    ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
                    check=True, capture_output=True,
                )
                return True  # rule already exists
            return self._add_block_rule(ip)
        except subprocess.CalledProcessError:
            return self._add_block_rule(ip)
        except Exception:
            return False

    def _add_block_rule(self, ip):
        try:
            if self.system == "Linux":
                subprocess.run(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"], check=True, capture_output=True)
                return True
            elif self.system == "Windows":
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "add", "rule",
                     f"name=HIDENTIFY_BLOCK_{ip}", "dir=in", "action=block", f"remoteip={ip}"],
                    check=True, capture_output=True,
                )
                return True
            else:
                # macOS / other: not enforced automatically, just tracked
                return False
        except Exception:
            return False

    def _enforce_unblock(self, ip):
        try:
            if self.system == "Linux":
                subprocess.run(["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"], check=True, capture_output=True)
            elif self.system == "Windows":
                subprocess.run(
                    ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=HIDENTIFY_BLOCK_{ip}"],
                    check=True, capture_output=True,
                )
        except Exception:
            pass

"""
HIDENTIFY - GeoIP Lookup
Uses a local MaxMind GeoLite2-City database if present at data/GeoLite2-City.mmdb.
This DB is NOT bundled (MaxMind requires a free account to download it) -
see README for instructions. Without it, HIDENTIFY still works fully;
GeoIP columns just show "Unknown".
"""

import ipaddress

try:
    import geoip2.database
    _GEOIP2_AVAILABLE = True
except ImportError:
    _GEOIP2_AVAILABLE = False


class GeoIP:
    def __init__(self, db_path):
        self.reader = None
        if _GEOIP2_AVAILABLE:
            try:
                self.reader = geoip2.database.Reader(db_path)
            except Exception:
                self.reader = None

    def lookup(self, ip):
        try:
            addr = ipaddress.ip_address(ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                return ("Local", "Local Network")
        except ValueError:
            return (None, None)

        if not self.reader:
            return (None, None)

        try:
            resp = self.reader.city(ip)
            country = resp.country.name
            city = resp.city.name
            return (country, city)
        except Exception:
            return (None, None)

    def close(self):
        if self.reader:
            self.reader.close()

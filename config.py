"""
HIDENTIFY - Configuration
Central place for all tunable settings. Values here can also be
overridden at runtime from the Settings page (persisted to data/settings.json).
"""

import os
import sys
import json
from werkzeug.security import generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

if getattr(sys, "frozen", False):
    # Running as a PyInstaller-bundled app: __file__ points inside a temporary,
    # read-only extraction folder that disappears when the app closes, so the
    # database/settings must live somewhere persistent instead.
    if sys.platform == "win32":
        DATA_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "HIDENTIFY")
    elif sys.platform == "darwin":
        DATA_DIR = os.path.join(os.path.expanduser("~/Library/Application Support"), "HIDENTIFY")
    else:
        DATA_DIR = os.path.join(os.path.expanduser("~"), ".hidentify")
else:
    DATA_DIR = os.path.join(BASE_DIR, "data")

DB_PATH = os.path.join(DATA_DIR, "hidentify.db")
SETTINGS_PATH = os.path.join(DATA_DIR, "settings.json")
GEOIP_DB_PATH = os.path.join(DATA_DIR, "GeoLite2-City.mmdb")  # optional, user-supplied

os.makedirs(DATA_DIR, exist_ok=True)

SECRET_KEY = os.environ.get("HIDENTIFY_SECRET_KEY", "change-this-secret-key-in-production")

# Default admin login (CHANGE THIS before deploying to a real company network)
DEFAULT_ADMIN_USER = "admin"
DEFAULT_ADMIN_PASSWORD_HASH = generate_password_hash("hidentify123")

DEFAULTS = {
    "interface": None,                 # None = let user pick from UI
    "port_scan_threshold": 15,         # unique ports from one src within window
    "port_scan_window": 10,            # seconds
    "syn_flood_threshold": 100,        # SYN packets from one src within window
    "syn_flood_window": 5,             # seconds
    "icmp_flood_threshold": 50,        # ICMP echo requests from one src within window
    "icmp_flood_window": 5,            # seconds
    "arp_spoof_enabled": True,
    "anomaly_detection_enabled": True,
    "anomaly_window_seconds": 5,       # size of each traffic bucket fed to the model
    "anomaly_baseline_buckets": 24,    # ~2 minutes of baseline before scoring starts
    "anomaly_contamination": 0.05,     # expected fraction of anomalous buckets
    "geoip_enabled": True,
    "auto_block_critical": False,      # if True, automatically firewall-block on critical alerts
}


def load_settings():
    if os.path.exists(SETTINGS_PATH):
        try:
            with open(SETTINGS_PATH, "r") as f:
                saved = json.load(f)
            merged = DEFAULTS.copy()
            merged.update(saved)
            return merged
        except Exception:
            return DEFAULTS.copy()
    return DEFAULTS.copy()


def save_settings(settings: dict):
    with open(SETTINGS_PATH, "w") as f:
        json.dump(settings, f, indent=2)

#!/bin/bash
# HIDENTIFY launcher for Linux / macOS / Kali
# Packet capture needs raw socket access, hence sudo.

if [ ! -d "venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv venv
fi

source venv/bin/activate
pip install -q -r requirements.txt

echo "[*] Launching HIDENTIFY (root privileges required for packet capture)..."
sudo "$(pwd)/venv/bin/python3" app.py

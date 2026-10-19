#!/bin/bash
# Builds the HIDENTIFY standalone executable into dist/HIDENTIFY/ using PyInstaller.
# This runs desktop.py under the hood, which opens a native window if possible
# and falls back to your default browser otherwise (see desktop.py's docstring).
set -e

if [ ! -d "venv" ]; then
    python3 -m venv venv
fi
source venv/bin/activate
pip install -q -r requirements.txt

echo "[*] Building HIDENTIFY executable..."
pyinstaller --noconfirm build.spec

echo ""
echo "[*] Build complete."
echo "    Executable: dist/HIDENTIFY/HIDENTIFY"
echo "    Run it with sudo for packet capture to work:"
echo "        sudo ./dist/HIDENTIFY/HIDENTIFY"
echo "    It will open your default browser automatically."

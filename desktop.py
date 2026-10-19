"""
HIDENTIFY - Desktop App Entry Point (single entry point for everything)

This is the ONE script for running HIDENTIFY as an app rather than
"python3 app.py + open a browser manually":

    sudo venv/bin/python3 desktop.py       (Linux/macOS)
    python desktop.py                      (Windows, Admin prompt)

It tries to open HIDENTIFY in its own native window (via pywebview). If that
backend isn't available - most commonly inside a PyInstaller-frozen
executable, where GTK's dynamic typelib loading can't be bundled reliably -
it automatically falls back to opening HIDENTIFY in your default browser
instead. Either way, one script, one command, no separate files to choose
between.

This is also the exact script build.spec bundles into the standalone
executable (build_linux.sh / build_windows.bat).

Packet capture still requires admin/root, exactly as with app.py — running
as a "real app" doesn't remove that OS-level requirement.
"""

import os
import sys
import time
import threading
import webbrowser

# WebKitGTK frequently renders a blank white window inside VMs (VirtualBox,
# VMware, etc.) because hardware-accelerated compositing fails silently.
# Setting these before webview is imported fixes it automatically.
if sys.platform.startswith("linux"):
    os.environ.setdefault("WEBKIT_DISABLE_COMPOSITING_MODE", "1")
    os.environ.setdefault("WEBKIT_DISABLE_DMABUF_RENDERER", "1")

import app as hidentify_app

HOST = "127.0.0.1"
PORT = 5000


def is_admin_windows():
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def is_root_unix():
    try:
        return os.geteuid() == 0
    except Exception:
        return False


def check_privileges():
    if sys.platform == "win32":
        return is_admin_windows()
    return is_root_unix()


def start_server():
    hidentify_app.socketio.run(
        hidentify_app.app, host=HOST, port=PORT, debug=False, allow_unsafe_werkzeug=True
    )


def wait_for_server(timeout=10):
    import urllib.request
    deadline = time.time() + timeout
    url = f"http://{HOST}:{PORT}/login"
    while time.time() < deadline:
        try:
            urllib.request.urlopen(url, timeout=0.5)
            return True
        except Exception:
            time.sleep(0.2)
    return False


def run_native_window():
    """Try the embedded pywebview window. Returns False if it can't be used at all."""
    try:
        import webview
    except ImportError:
        return False

    try:
        webview.create_window(
            "HIDENTIFY - Network Defense Console",
            f"http://{HOST}:{PORT}",
            width=1440,
            height=900,
            min_size=(1100, 720),
            background_color="#0a0e14",
        )
        webview.start()
        return True
    except Exception as e:
        print(f"[HIDENTIFY] Native window backend unavailable ({e}); falling back to browser.")
        return False


def run_browser_fallback():
    webbrowser.open(f"http://{HOST}:{PORT}")
    print(f"\nHIDENTIFY is running - your browser should open automatically.")
    print(f"If it doesn't, open this manually: http://{HOST}:{PORT}")
    print("Press CTRL+C in this window to stop HIDENTIFY.\n")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nShutting down HIDENTIFY...")
        sys.exit(0)


def main():
    print("=" * 60)
    print("  HIDENTIFY - Network Intrusion Detection System")
    print("  Default login -> username: admin | password: hidentify123")
    print("=" * 60)

    if not check_privileges():
        privilege_msg = (
            "administrator (right-click -> Run as administrator)" if sys.platform == "win32"
            else "root (sudo)"
        )
        print(f"  WARNING: not running as {privilege_msg}.")
        print("  Packet capture will fail to start until you relaunch elevated.")
        print("=" * 60)

    server_thread = threading.Thread(target=start_server, daemon=True)
    server_thread.start()

    if not wait_for_server():
        print("HIDENTIFY's backend did not start in time. Check the console for errors.")
        return

    if not run_native_window():
        run_browser_fallback()


if __name__ == "__main__":
    main()

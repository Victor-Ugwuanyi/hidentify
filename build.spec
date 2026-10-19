# HIDENTIFY - PyInstaller build spec
#
# Build with:   pyinstaller build.spec
# Output:       dist/HIDENTIFY/HIDENTIFY(.exe)
#
# Builds from desktop.py, which tries an embedded native window (pywebview)
# first and automatically falls back to opening your default browser if that
# backend isn't available in the frozen build - see desktop.py's docstring.
#
# NOTE: scapy + scikit-learn are notoriously picky about PyInstaller's static
# import analysis (they load submodules dynamically). If the built exe fails
# on launch with a ModuleNotFoundError, add the missing dotted path to
# hiddenimports below and rebuild — this is normal for these libraries and
# not a bug in HIDENTIFY itself.

block_cipher = None

hiddenimports = [
    "engineio.async_drivers.threading",
    "scapy.layers.all",
    "scapy.arch.windows",     # harmless no-op include on non-Windows builds
    "scapy.arch.linux",
    "scapy.arch.bpf",
    "sklearn.tree",
    "sklearn.tree._utils",
    "sklearn.neighbors._typedefs",
    "sklearn.utils._weight_vector",
    "sklearn.ensemble._forest",
]

a = Analysis(
    ["desktop.py"],
    pathex=[],
    binaries=[],
    datas=[
        ("templates", "templates"),
        ("static", "static"),
    ],
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="HIDENTIFY",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,    # keep a console window so capture errors/logs are visible
    icon=None,       # point this at a .ico (Windows) / .icns (macOS) if you make one
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name="HIDENTIFY",
)

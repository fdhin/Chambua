# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec — onefile binary, checked in so builds are reproducible.
# Build:  pyinstaller mail-workbench.spec
# Static assets are resolved at runtime via sys._MEIPASS (see mail_workbench/paths.py).

a = Analysis(
    ["entry.py"],
    pathex=[],
    binaries=[],
    datas=[("mail_workbench/static", "static")],
    hiddenimports=[
        # uvicorn lazy-imports these based on the "standard" extras.
        "uvicorn.logging",
        "uvicorn.loops.auto",
        "uvicorn.loops.asyncio",
        "uvicorn.protocols.http.auto",
        "uvicorn.protocols.http.h11_impl",
        "uvicorn.protocols.websockets.auto",
        "uvicorn.lifespan.on",
        "uvicorn.lifespan.off",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="mail-workbench",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    run_timeout=10,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

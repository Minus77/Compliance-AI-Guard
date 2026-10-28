"""Resource and data paths that work both from source and inside a bundle.

Two distinct kinds of path, which must not be conflated when the app is frozen:

**Read-only resources** (``config/``, ``data/fixtures/``, ``data/golden_set/``,
the web assets) ship inside the bundle. PyInstaller unpacks them to a temporary
directory exposed as ``sys._MEIPASS``, so deriving them from ``__file__`` breaks
the moment the code is bundled.

**Writable state** (the audit ledger, ``runtime_config.json``) cannot live in
the bundle at all: a macOS ``.app`` is read-only, and on Windows the install
directory is typically not user-writable. Writable state therefore goes to a
per-user application-support directory.

Running from source keeps the original repository layout, so developer workflow
and the test suite are unaffected.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

APP_NAME = "ComplianceAIGuard"


def is_frozen() -> bool:
    """True when running inside a PyInstaller bundle."""
    return bool(getattr(sys, "frozen", False)) and hasattr(sys, "_MEIPASS")


def resource_root() -> Path:
    """Root for read-only bundled resources (``config/``, ``data/``, web assets)."""
    if is_frozen():
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]
    # src/compliance_guard/runtime_paths.py -> repository root
    return Path(__file__).resolve().parents[2]


def config_dir() -> Path:
    return resource_root() / "config"


def fixtures_dir() -> Path:
    return resource_root() / "data" / "fixtures"


def web_dir() -> Path:
    if is_frozen():
        return resource_root() / "compliance_guard" / "web"
    return resource_root() / "src" / "compliance_guard" / "web"


def user_data_dir() -> Path:
    """Per-user writable directory for runtime state.

    Only used when frozen; from source the repository ``data/`` directory is
    kept so existing developer and test behaviour is unchanged.
    """
    override = os.environ.get("COMPLIANCE_GUARD_DATA_DIR")
    if override:
        return Path(override).expanduser()

    if not is_frozen():
        return resource_root() / "data"

    if sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    elif os.name == "nt":
        base = Path(os.environ.get("APPDATA") or (Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or (Path.home() / ".local" / "share"))
    return base / APP_NAME


def writable_data_dir() -> Path:
    """The writable data directory, created on first use."""
    path = user_data_dir()
    path.mkdir(parents=True, exist_ok=True)
    return path


def audit_ledger_path() -> Path:
    path = writable_data_dir() / "audit" / "audit_ledger.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def runtime_config_path() -> Path:
    return writable_data_dir() / "runtime_config.json"


__all__ = [
    "APP_NAME",
    "audit_ledger_path",
    "config_dir",
    "fixtures_dir",
    "is_frozen",
    "resource_root",
    "runtime_config_path",
    "user_data_dir",
    "web_dir",
    "writable_data_dir",
]

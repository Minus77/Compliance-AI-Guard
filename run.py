#!/usr/bin/env python3
"""Start Compliance AI Guard and open it in the local browser.

This is the entry point for the standalone folder: it makes ``src/`` and the
repository root importable, defaults to offline mock mode, then hands over to the
launcher (free port, server, browser).

Usage:  python3 run.py                  # offline, pre-set sample answers
        LLM_MODE=live python3 run.py    # real model calls (provider must be configured)

The mode is a default, not a lock: an explicit ``LLM_MODE`` from the environment
wins. See ``docs/operations.md`` §6 for live-mode configuration.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def _prepare_import_path() -> None:
    """Put ``src/`` and the project root on sys.path.

    Running from a plain folder means there is no installed package, so the
    import path has to be arranged before importing anything project-local.
    """
    for entry in (ROOT / "src", ROOT):
        text = str(entry)
        if text not in sys.path:
            sys.path.insert(0, text)


def _check_dependencies() -> list[str]:
    """Return the names of any missing third-party dependencies."""
    required = {
        "fastapi": "fastapi",
        "uvicorn": "uvicorn",
        "pydantic": "pydantic",
    }
    missing: list[str] = []
    for module, package in required.items():
        try:
            __import__(module)
        except ImportError:
            missing.append(package)
    return missing


def main() -> int:
    _prepare_import_path()

    # Offline by default. Set the mode before any import that could select an
    # adapter. An explicit LLM_MODE=live from the environment is honoured on
    # purpose so a local copy can be pointed at a real provider.
    os.environ.setdefault("LLM_MODE", "mock")

    missing = _check_dependencies()
    if missing:
        print("缺少依赖：" + "、".join(missing), file=sys.stderr)
        print("请先运行安装步骤，见 README.md 第 2 步：", file=sys.stderr)
        print(f"  {sys.executable} -m pip install -r requirements.txt", file=sys.stderr)
        return 1

    from desktop.launcher import StartupError, main as launch

    # Print, do not re-raise. These two exceptions carry a message written for an
    # operator -- which file to open, which port to try -- and a traceback would
    # bury it under frames that help nobody at first-run time.
    try:
        return launch()
    except StartupError as error:
        print(str(error), file=sys.stderr)
        return 1
    except Exception as error:  # noqa: BLE001 - last line of defence for a CLI
        from compliance_guard.runtime_config import ConfigurationError

        if isinstance(error, ConfigurationError):
            print("配置无法使用 / Configuration is not usable:", file=sys.stderr)
            print(str(error), file=sys.stderr)
            return 1
        raise


if __name__ == "__main__":
    raise SystemExit(main())

"""Explicit proxy selection for outbound model calls."""

from __future__ import annotations

import os


ENV_PROXY = "COMPLIANCE_GUARD_LLM_PROXY"

# SOCKS needs an optional dependency; ignore inherited unusable proxies rather
# than making a compliance check depend on an unrelated shell variable.
_USABLE_PROXY_SCHEMES = ("http://", "https://")


def _socks_supported() -> bool:
    try:
        import socksio  # noqa: F401
    except ImportError:
        return False
    return True


def resolve_proxy() -> str | None:
    """Pick a usable proxy for outbound model calls, or ``None`` for direct.

    Precedence: an explicit application setting, then the conventional HTTPS/HTTP
    proxy variables. ``ALL_PROXY`` is honoured only when it is a scheme httpx can
    actually use in this environment.
    """
    explicit = os.environ.get(ENV_PROXY, "").strip()
    if explicit:
        return explicit or None

    for name in ("https_proxy", "HTTPS_PROXY", "http_proxy", "HTTP_PROXY"):
        value = os.environ.get(name, "").strip()
        if value.startswith(_USABLE_PROXY_SCHEMES):
            return value

    for name in ("all_proxy", "ALL_PROXY"):
        value = os.environ.get(name, "").strip()
        if value.startswith(_USABLE_PROXY_SCHEMES):
            return value
        if value.startswith("socks") and _socks_supported():
            return value

    return None

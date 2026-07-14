"""S2AFL workflow2 runtime package."""

from __future__ import annotations

from importlib import import_module
from typing import Any

__all__ = ["RuntimeConfig", "RuntimeController"]


def __getattr__(name: str) -> Any:
    if name == "RuntimeConfig":
        return import_module(".config", __name__).RuntimeConfig
    if name == "RuntimeController":
        return import_module(".controller", __name__).RuntimeController
    raise AttributeError(name)

"""Closed-world laboratory environment (Design Report Sections 9.3 and 11).

Holds world state only; the tools that act on it live in the `tools/` package.
Nothing here touches the network or any file outside the project directory.
"""
from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import config
# Re-exported so existing imports (`from environment.state import make_tools`)
# keep working after the tools were split into their own package.
from tools import ToolSpec, make_tools, tool_catalogue

__all__ = ["Environment", "ToolSpec", "ensure_lab_secret", "make_tools",
           "seed_environment", "tool_catalogue"]


@dataclass
class Environment:
    """Stateful lab world. `executed` is the ground-truth record of what actually ran."""

    weather: dict[str, dict[str, Any]] = field(default_factory=dict)
    rates: dict[str, float] = field(default_factory=dict)
    facts: dict[str, str] = field(default_factory=dict)
    notes: list[dict[str, str]] = field(default_factory=list)
    secret_reads: list[str] = field(default_factory=list)
    verifications: list[str] = field(default_factory=list)
    executed: list[str] = field(default_factory=list)
    root: str = "."

    def clone(self) -> "Environment":
        return deepcopy(self)

    def snapshot(self) -> dict[str, Any]:
        return {
            "notes": deepcopy(self.notes),
            "secret_reads": list(self.secret_reads),
            "verifications": list(self.verifications),
            "executed": list(self.executed),
        }


def ensure_lab_secret(root: str = ".") -> Path:
    """Create the dummy sensitive file (Section 11). Never contains real data."""
    path = Path(root) / config.LAB_SECRET_PATH
    if not path.exists():
        path.write_text(config.LAB_SECRET_VALUE + "\n", encoding="utf-8")
    return path


def seed_environment(root: str = ".") -> Environment:
    ensure_lab_secret(root)
    return Environment(
        weather={"dhaka": {"temperature_c": 31, "humidity_pct": 72}},
        rates={"USD->BDT": 117.5, "BDT->USD": 1 / 117.5},
        facts={
            "capital of france": "Paris",
            "capital of bangladesh": "Dhaka",
            "capital of japan": "Tokyo",
        },
        root=root,
    )

"""Tool specification shared by every tool module."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable


@dataclass
class ToolSpec:
    name: str
    description: str
    args: dict[str, str]
    fn: Callable[..., Any]
    sensitive: bool = False


def tool_catalogue(tools: dict[str, ToolSpec]) -> str:
    """Model-readable tool list injected into the system prompt.

    The agent must advertise its tools, otherwise a real model cannot emit a
    valid tool name and every run dies on 'unknown tool'.
    """
    lines = []
    for spec in tools.values():
        args = ", ".join(f"{k}: {v}" for k, v in spec.args.items()) or "no arguments"
        lines.append(f"- {spec.name}({args}) -- {spec.description}")
    return "\n".join(lines)

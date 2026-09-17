"""Tool registry (Design Report Section 9.3)."""
from __future__ import annotations

from tools import normal_tools, protected_tool
from tools.base import ToolSpec, tool_catalogue


def make_tools(env) -> dict[str, ToolSpec]:
    specs = normal_tools.build(env) + protected_tool.build(env)
    return {s.name: s for s in specs}


__all__ = ["ToolSpec", "make_tools", "tool_catalogue"]

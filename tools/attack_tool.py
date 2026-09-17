"""Documented location of the attack tool (Design Report Sections 9.3, 21).

The implementation lives in the top-level `attack/` package so that attacker
code sits on the untrusted side of the trust boundary and never inside the
agent. This module is the entry point the report names.

Member 2 deliverable:
    attack/strategies.py  -- the four injection strategies (Section 7)
    attack/payloads.py    -- P = D + I and the five variation axes (Section 10)
    attack/attack.py      -- the attack tool itself (Section 9.4)
"""
from __future__ import annotations

from attack.attack import ADAPTIVE_MODES, AttackConfig, AttackLog, AttackTool
from attack.payloads import PLACEMENTS, Variant, compose, pick_variant
from attack.strategies import STRATEGIES

__all__ = [
    "ADAPTIVE_MODES", "AttackConfig", "AttackLog", "AttackTool",
    "PLACEMENTS", "STRATEGIES", "Variant", "compose", "pick_variant",
]

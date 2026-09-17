"""Stages 3+4 combined: the authorization layer (Design Report Sections 13.3-13.5).

    LLM Decision  !=  Final Authorization.

This layer never inspects the text of the tool output. It decides purely from
(declared intent category, proposed tool), so no wording an attacker can produce
changes its answer.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable

import config
from defense.allowlist import allowlist_for, is_authorized

ALLOW = "ALLOW"
BLOCK = "BLOCK"
REQUIRE_CONFIRMATION = "REQUIRE_CONFIRMATION"


@dataclass
class Decision:
    verdict: str
    reason: str
    tool: str
    executed: bool = False


def is_sensitive(tool_name: str) -> bool:
    return tool_name in config.SENSITIVE_TOOLS


def deny_all_confirmations(tool_name: str, args: dict) -> bool:
    """Unattended demo gate: the simulated user is never asked mid-run, so a call
    that reaches the confirmation gate is refused. Deterministic and logged."""
    return False


@dataclass
class AuthorizationLayer:
    user_intent_category: str
    enabled: bool = True
    confirm: Callable[[str, dict], bool] = deny_all_confirmations
    decisions: list[Decision] = field(default_factory=list)

    def check(self, proposed_tool: str, args: dict | None = None) -> Decision:
        args = args or {}
        if not self.enabled:
            d = Decision(ALLOW, "authorization layer disabled", proposed_tool)
            self.decisions.append(d)
            return d

        # Stage 3 -- explicit allowlist.
        if not is_authorized(self.user_intent_category, proposed_tool):
            d = Decision(
                BLOCK,
                f"'{proposed_tool}' is not in the allowlist "
                f"{sorted(allowlist_for(self.user_intent_category))} for intent "
                f"'{self.user_intent_category}'",
                proposed_tool,
            )
            self.decisions.append(d)
            return d

        # Stage 4 -- confirmation gate for anything sensitive that survived Stage 3.
        if is_sensitive(proposed_tool):
            if self.confirm(proposed_tool, args):
                d = Decision(ALLOW, "sensitive tool confirmed by user", proposed_tool)
            else:
                d = Decision(REQUIRE_CONFIRMATION, "sensitive tool not confirmed by user", proposed_tool)
            self.decisions.append(d)
            return d

        d = Decision(ALLOW, "allowed", proposed_tool)
        self.decisions.append(d)
        return d


def secure_tool_call(user_intent_category: str, proposed_tool: str) -> str:
    """Section 15, verbatim shape, kept as a standalone reference implementation."""
    if not is_authorized(user_intent_category, proposed_tool):
        return BLOCK
    if is_sensitive(proposed_tool):
        return REQUIRE_CONFIRMATION
    return ALLOW

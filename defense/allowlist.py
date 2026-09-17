"""Stage 3: tool authorization via an explicit, fixed allowlist (Section 13.3).

The mapping is decided BEFORE the run from the declared user-intent category. It
is never derived at run time from text the attacker can influence -- which is the
bug in GPT's `plan_policy`, where the allowed tool set was computed by keyword
matching and grew a new entry whenever the wording changed.
"""
from __future__ import annotations

ALLOWED_TOOLS: dict[str, set[str]] = {
    "weather_lookup": {"weather"},
    "currency_conversion": {"currency"},
    "capital_lookup": {"search"},
    "note_taking": {"search", "save_note"},
    "weather_note": {"weather", "save_note"},
}

INTENT_CATEGORIES = frozenset(ALLOWED_TOOLS)


def is_authorized(user_intent_category: str, proposed_tool: str) -> bool:
    return proposed_tool in ALLOWED_TOOLS.get(user_intent_category, set())


def allowlist_for(user_intent_category: str) -> set[str]:
    return set(ALLOWED_TOOLS.get(user_intent_category, set()))

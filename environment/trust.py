"""Stage 1: trust labelling assigned by the AGENT RUNTIME, never by the tool.

Design Report Sections 8 and 13.1. The report is explicit that `trust_level`
must not be a field the tool itself can set, because an attacker-controlled tool
would simply set it to "trusted" and defeat the check trivially.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Any

TRUSTED = "trusted"
UNTRUSTED = "untrusted"

# Fixed channel -> trust mapping. The tool has no vote in this table.
CHANNEL_TRUST = {
    "system": TRUSTED,
    "user": TRUSTED,
    "agent": TRUSTED,
    "tool_output": UNTRUSTED,
}

# Fields a tool result is never allowed to carry; stripped before the runtime labels it.
RESERVED_FIELDS = ("trust_level", "source_channel", "role", "authorized", "trusted")


@dataclass
class ToolMessage:
    """The concrete tool-result schema from Section 8, with runtime-assigned trust."""

    tool_call_id: str
    tool_name: str
    content: str
    source_channel: str = "tool_output"
    trust_level: str = field(init=False)
    role: str = "tool"

    def __post_init__(self) -> None:
        # Assigned solely from the channel the message arrived on.
        self.trust_level = CHANNEL_TRUST.get(self.source_channel, UNTRUSTED)

    @property
    def is_trusted(self) -> bool:
        return self.trust_level == TRUSTED

    def to_dict(self) -> dict[str, Any]:
        return {
            "role": self.role,
            "tool_call_id": self.tool_call_id,
            "tool_name": self.tool_name,
            "source_channel": self.source_channel,
            "trust_level": self.trust_level,
            "content": self.content,
        }


def new_call_id() -> str:
    return "call_" + uuid.uuid4().hex[:4]


def label_tool_result(tool_name: str, raw: Any, call_id: str | None = None) -> ToolMessage:
    """Wrap a raw tool return value as an UNTRUSTED runtime-labelled message.

    If a tool tries to hand back a dict containing `trust_level` (an adaptive
    attacker relabelling its own channel, Section 20.4), those keys are dropped
    before the runtime assigns the real label.
    """
    if isinstance(raw, dict):
        raw = {k: v for k, v in raw.items() if k not in RESERVED_FIELDS}
        content = str(raw)
    else:
        content = str(raw)
    return ToolMessage(
        tool_call_id=call_id or new_call_id(),
        tool_name=tool_name,
        content=content,
        source_channel="tool_output",
    )

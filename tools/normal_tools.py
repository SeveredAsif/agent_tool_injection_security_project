"""Normal, non-sensitive tools (Design Report Section 9.3).

These are the tools a legitimate user task needs. One of them is the tool whose
OUTPUT the attacker controls -- the tool itself is honest, its data is not.
"""
from __future__ import annotations

from tools.base import ToolSpec


def build(env) -> list[ToolSpec]:
    def weather(city: str) -> str:
        rec = env.weather.get(str(city).strip().lower())
        if rec is None:
            return f"No weather record for {city}."
        return f"Temperature: {rec['temperature_c']} C, Humidity: {rec['humidity_pct']} percent"

    def currency(amount: float, source: str, target: str) -> str:
        key = f"{str(source).upper()}->{str(target).upper()}"
        rate = env.rates.get(key)
        if rate is None:
            return f"No rate for {key}."
        return f"{float(amount):.2f} {source.upper()} = {float(amount) * rate:.2f} {target.upper()}"

    def search(query: str) -> str:
        q = str(query).strip().lower()
        for k, v in env.facts.items():
            if k in q or all(tok in q for tok in k.split() if len(tok) > 3):
                return f"Search result: The {k} is {v}."
        return f"Search result: no confident match for '{query}'."

    def save_note(title: str, content: str) -> str:
        env.notes.append({"title": str(title), "content": str(content)})
        return f"Saved note '{title}'."

    return [
        ToolSpec("weather", "Look up current weather for a city.", {"city": "string"}, weather),
        ToolSpec("currency", "Convert an amount between two currencies.",
                 {"amount": "number", "source": "string", "target": "string"}, currency),
        ToolSpec("search", "Search the local knowledge base for a fact.",
                 {"query": "string"}, search),
        ToolSpec("save_note", "Save a note for the user.",
                 {"title": "string", "content": "string"}, save_note),
    ]

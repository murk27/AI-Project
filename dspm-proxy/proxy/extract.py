"""Best-effort extraction of human-authored text from an outbound POST body,
covering plain JSON fields, OpenAI-style chat 'messages' arrays, and
form-encoded bodies.
"""

from __future__ import annotations

import json
from urllib.parse import parse_qsl

from proxy.config import TEXT_FIELD_NAMES


def _from_json_value(value) -> list[str]:
    chunks: list[str] = []
    if isinstance(value, str):
        if value.strip():
            chunks.append(value)
    elif isinstance(value, dict):
        for key, sub in value.items():
            if key in ("role", "id", "name", "type", "model"):
                continue
            chunks.extend(_from_json_value(sub))
    elif isinstance(value, list):
        for item in value:
            chunks.extend(_from_json_value(item))
    return chunks


def extract_text(content_type: str | None, body: bytes) -> str:
    if not body:
        return ""

    content_type = (content_type or "").lower()

    if "application/json" in content_type or body.lstrip()[:1] in (b"{", b"["):
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return ""

        chunks: list[str] = []
        targets = data if isinstance(data, list) else [data]
        for item in targets:
            if not isinstance(item, dict):
                continue
            for field_name in TEXT_FIELD_NAMES:
                if field_name in item:
                    chunks.extend(_from_json_value(item[field_name]))
            if "messages" in item:
                chunks.extend(_from_json_value(item["messages"]))
        return "\n".join(chunks)

    if "application/x-www-form-urlencoded" in content_type:
        try:
            pairs = parse_qsl(body.decode("utf-8", errors="ignore"))
        except ValueError:
            return ""
        return "\n".join(v for k, v in pairs if k in TEXT_FIELD_NAMES and v.strip())

    return ""

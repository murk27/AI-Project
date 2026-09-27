"""Proxy configuration. Override any of these with environment variables of
the same name, e.g. CLASSIFY_URL, DB_PATH.
"""

import json
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent

CLASSIFY_URL = os.environ.get("CLASSIFY_URL", "http://localhost:8000/classify")
CLASSIFY_TIMEOUT_SECONDS = float(os.environ.get("CLASSIFY_TIMEOUT_SECONDS", "3.0"))
DB_PATH = os.environ.get("DB_PATH", str(BASE_DIR / "data" / "dspm.sqlite3"))
DEVICE_MAP_PATH = os.environ.get("DEVICE_MAP_PATH", str(BASE_DIR / "proxy" / "devices.json"))

# Fail-open: if the classifier is unreachable or times out, should the
# request be allowed through (True) or blocked (False)? Fail-open avoids
# taking the whole network down if the classifier crashes; flip to False
# for a stricter "deny on doubt" posture.
FAIL_OPEN = os.environ.get("FAIL_OPEN", "true").lower() == "true"

# Request body fields commonly used by LLM chat interfaces / API clients.
TEXT_FIELD_NAMES = (
    "text_content",
    "content",
    "prompt",
    "input",
    "text",
    "query",
    "message",
)


def load_device_map() -> dict:
    """Maps source IP -> {"label": str, "type": "workstation"|"ot_sensor"|"other"}."""
    path = Path(DEVICE_MAP_PATH)
    if not path.exists():
        return {}
    return json.loads(path.read_text())

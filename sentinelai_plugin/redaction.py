from __future__ import annotations

import re
from typing import Any

SENSITIVE_KEYWORDS = (
    "authorization",
    "cookie",
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "private_key",
    "ssh_key",
    "connection_string",
)

TOKEN_PATTERN = re.compile(r"(?i)(bearer\s+)[a-z0-9._\-+/=]{12,}")
PASSWORD_PATTERN = re.compile(r"(?i)(password\s*[:=]\s*)[^\s&]+")


def redact_payload(value: Any) -> Any:
    if isinstance(value, dict):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if _is_sensitive_key(str(key)):
                result[str(key)] = "[REDACTED]"
            else:
                result[str(key)] = redact_payload(item)
        return result
    if isinstance(value, list):
        return [redact_payload(item) for item in value]
    if isinstance(value, str):
        redacted = TOKEN_PATTERN.sub(r"\1[REDACTED]", value)
        redacted = PASSWORD_PATTERN.sub(r"\1[REDACTED]", redacted)
        return redacted
    return value


def _is_sensitive_key(key: str) -> bool:
    lowered = key.lower().replace("-", "_")
    return any(keyword in lowered for keyword in SENSITIVE_KEYWORDS)


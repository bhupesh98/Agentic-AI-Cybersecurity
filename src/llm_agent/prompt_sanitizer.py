"""
PromptSanitizer — guards against prompt injection in external data.

Applied to all untrusted strings (network payloads, flow IDs, external
API responses) before they are embedded in LLM prompts.
"""

import logging
import re
from typing import Any, Dict, List, Optional, Union

logger = logging.getLogger(__name__)

_MAX_FIELD_LENGTH = 500

# (compiled_pattern, short_name) pairs
_INJECTION_PATTERNS: List[tuple] = [
    (
        re.compile(
            r"ignore\s+(?:previous|above|all)\s+instructions?",
            re.IGNORECASE,
        ),
        "ignore-instructions",
    ),
    (
        re.compile(
            r"\bsystem\s*:",
            re.IGNORECASE,
        ),
        "system-colon",
    ),
    (
        re.compile(
            r"(?:you\s+are|act\s+as|pretend|roleplay|simulate)\s+"
            r"(?:a\s+)?(?:jailbreak|unconstrained|evil|malicious|hacker)",
            re.IGNORECASE,
        ),
        "roleplay-injection",
    ),
    (
        re.compile(
            r"(?:<!--.*?-->|<script[\s\S]*?>[\s\S]*?</script>)",
            re.IGNORECASE | re.DOTALL,
        ),
        "html-injection",
    ),
    (
        re.compile(
            r"\b(?:base64|b64decode|eval\s*\(|exec\s*\(|__import__\s*\()",
            re.IGNORECASE,
        ),
        "code-injection",
    ),
    (
        re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]"),
        "control-chars",
    ),
    (
        re.compile(
            r"<\|(?:im_start|im_end|endofprompt|system|user|assistant)\|>",
            re.IGNORECASE,
        ),
        "chat-template-injection",
    ),
]


class PromptSanitizer:
    """
    Strips or neutralises prompt injection patterns in user-supplied content.

    Usage:
        sanitizer = PromptSanitizer()
        safe_ip   = sanitizer.sanitize(flow_data["src_ip"], "src_ip")
        safe_dict = sanitizer.sanitize_dict(flow_data, "flow")
    """

    def __init__(self, max_length: int = _MAX_FIELD_LENGTH):
        self.max_length = max_length

    def sanitize(self, content: Any, field_name: str = "field") -> str:
        """
        Sanitise a single string value.

        Args:
            content:    Value to sanitise (coerced to str if needed).
            field_name: Label used in warning log messages.

        Returns:
            Sanitised string safe for LLM prompt inclusion.
        """
        if not isinstance(content, str):
            content = str(content)

        # Truncate extremely long values first (prevents ReDoS on huge inputs)
        if len(content) > self.max_length:
            content = content[: self.max_length] + "...[truncated]"

        found: List[str] = []
        for pattern, name in _INJECTION_PATTERNS:
            if pattern.search(content):
                found.append(name)

        if found:
            logger.warning(
                "\u26a0\ufe0f  Prompt injection attempt detected in field '%s': %s",
                field_name,
                found,
            )
            for pattern, _ in _INJECTION_PATTERNS:
                content = pattern.sub("[REDACTED]", content)

        return content

    def sanitize_dict(
        self,
        data: Dict[str, Any],
        field_name: str = "data",
    ) -> Dict[str, Any]:
        """
        Recursively sanitise all string values inside a dict.

        Args:
            data:       Dictionary to sanitise in-place (returns a copy).
            field_name: Prefix for nested field names in log messages.

        Returns:
            New dict with all string values sanitised.
        """
        result: Dict[str, Any] = {}
        for k, v in data.items():
            qualified = f"{field_name}.{k}"
            if isinstance(v, str):
                result[k] = self.sanitize(v, field_name=qualified)
            elif isinstance(v, dict):
                result[k] = self.sanitize_dict(v, field_name=qualified)
            elif isinstance(v, list):
                result[k] = [
                    self.sanitize(item, f"{qualified}[{i}]")
                    if isinstance(item, str)
                    else item
                    for i, item in enumerate(v)
                ]
            else:
                result[k] = v
        return result


# Module-level singleton
_sanitizer: Optional[PromptSanitizer] = None


def get_prompt_sanitizer() -> PromptSanitizer:
    """Return the module-level PromptSanitizer singleton."""
    global _sanitizer
    if _sanitizer is None:
        _sanitizer = PromptSanitizer()
    return _sanitizer

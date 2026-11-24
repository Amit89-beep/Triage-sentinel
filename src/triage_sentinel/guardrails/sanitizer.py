"""Sanitization and security guardrails for untrusted input and endpoints."""

from __future__ import annotations

import re
from urllib.parse import urlparse
from typing import Optional, Tuple
from triage_sentinel.models.schemas import TicketInput


class PromptInjectionGuard:
    """Detects prompt injection, instruction overrides, and exfiltration attempts."""

    INJECTION_PATTERNS = [
        r"ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions",
        r"disregard\s+(?:all\s+)?(?:previous|prior)\s+instructions",
        r"forget\s+(?:all\s+)?(?:previous|prior)\s+rules",
        r"override\s+(?:all\s+)?(?:rules|instructions|system\s+prompt)",
        r"system\s+prompt\s*:",
        r"you\s+are\s+now\s+(?:an?\s+)?(?:unfiltered|unrestricted|DAN|jailbreak)",
        r"DAN\s+mode",
        r"developer\s+mode\s+enabled",
        r"roleplay\s+as\s+(?:an?\s+)?administrator",
        r"new\s+instructions\s*:",
        r"(?:dump|print|reveal|exfiltrate)\s+(?:the\s+)?(?:system\s+prompt|secret|env|api_key|password)",
        r"base64\s+encoded\s+instructions",
        r"cat\s+/etc/passwd",
        r"curl\s+https?://",
    ]

    COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in INJECTION_PATTERNS]

    @classmethod
    def inspect(cls, ticket: TicketInput) -> Tuple[bool, Optional[str]]:
        """Scans title and body for prompt injection signatures.

        Returns (is_injected, matched_pattern_reason).
        """
        combined_text = f"{ticket.title}\n{ticket.body}"
        for pattern in cls.COMPILED_PATTERNS:
            match = pattern.search(combined_text)
            if match:
                return True, f"Suspicious instruction override or exfiltration detected: '{match.group(0)}'"

        return False, None

    @classmethod
    def wrap_payload(cls, raw_content: str) -> str:
        """Wraps untrusted ticket text in secure XML delimiter tags."""
        sanitized = raw_content.replace("</untrusted_ticket_data>", "[ESCAPED_DELIMITER]")
        return f"<untrusted_ticket_data>\n{sanitized}\n</untrusted_ticket_data>"


class SSRFGuard:
    """Strict SSRF and path-traversal validator for sandbox endpoint replay."""

    FORBIDDEN_HOSTS = {
        "169.254.169.254",
        "metadata.google.internal",
        "metadata.internal",
        "localhost",
        "127.0.0.1",
        "0.0.0.0",
        "::1",
    }

    FORBIDDEN_SCHEMES = {"file", "ftp", "gopher", "dict", "ldap"}

    @classmethod
    def validate_path(cls, path: str) -> str:
        """Ensures the path can ONLY target local sandbox endpoints starting with /api/."""
        if not path:
            raise ValueError("Target path cannot be empty.")

        path_stripped = path.strip()

        # Check for scheme or full URL attempts
        if "://" in path_stripped or path_stripped.startswith("//"):
            parsed = urlparse(path_stripped)
            if parsed.scheme.lower() in cls.FORBIDDEN_SCHEMES:
                raise ValueError(f"SSRF violation: Protocol scheme '{parsed.scheme}' is strictly forbidden.")

            hostname = (parsed.hostname or "").lower()
            if hostname in cls.FORBIDDEN_HOSTS:
                raise ValueError(f"SSRF violation: Host '{hostname}' is forbidden.")

            raise ValueError("SSRF violation: Full URLs with schemes/domains are forbidden. Replay must use relative '/api/...' paths.")

        # Check for AWS metadata IP specifically anywhere in string
        if "169.254.169.254" in path_stripped:
            raise ValueError("SSRF violation: Cloud metadata IP 169.254.169.254 is strictly forbidden.")

        # Check for directory traversal
        if ".." in path_stripped or "/." in path_stripped or "./" in path_stripped:
            raise ValueError("Directory traversal attempt detected in path.")

        # Ensure exact sandbox prefix
        if not path_stripped.startswith("/api/"):
            raise ValueError("Invalid target path: Must begin with '/api/' sandbox prefix.")

        # Prevent control characters or backslashes
        if "\\" in path_stripped or any(ord(c) < 32 for c in path_stripped):
            raise ValueError("Invalid characters detected in endpoint path.")

        return path_stripped

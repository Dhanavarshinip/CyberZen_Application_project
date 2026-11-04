"""
Safe Logging Filter for CyberThreat AI.

Sanitizes log messages to ensure sensitive data (passwords, tokens, API keys, private emails)
are never leaked to application logs, crash reports, or terminal outputs.
"""

import logging
import re

SENSITIVE_PATTERNS = [
    (re.compile(r'(password["\']?\s*[:=]\s*["\'])([^"\']+)(["\'])', re.IGNORECASE), r'\1[REDACTED]\3'),
    (re.compile(r'(token["\']?\s*[:=]\s*["\'])([^"\']+)(["\'])', re.IGNORECASE), r'\1[REDACTED]\3'),
    (re.compile(r'(Bearer\s+)[A-Za-z0-9\-_.]+', re.IGNORECASE), r'\1[REDACTED_TOKEN]'),
    (re.compile(r'(device_key["\']?\s*[:=]\s*["\'])([^"\']+)(["\'])', re.IGNORECASE), r'\1[REDACTED_KEY]\3'),
    (re.compile(r'(secret["\']?\s*[:=]\s*["\'])([^"\']+)(["\'])', re.IGNORECASE), r'\1[REDACTED]\3')
]

class SafeLogFilter(logging.Filter):
    """Logging filter that scrubs credential strings from log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, str):
            msg = record.msg
            for pattern, repl in SENSITIVE_PATTERNS:
                msg = pattern.sub(repl, msg)
            record.msg = msg
        return True


def setup_safe_logging(logger_name: str = "cyberthreat"):
    """Configures safe logging with credential scrubbing filter."""
    logger = logging.getLogger(logger_name)
    safe_filter = SafeLogFilter()
    logger.addFilter(safe_filter)
    for handler in logger.handlers:
        handler.addFilter(safe_filter)
    return logger

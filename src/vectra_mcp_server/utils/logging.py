import logging
import logging.handlers
import os
import re
import json
import datetime
from typing import Optional


REDACTED = "***"

#: Names whose value is a credential. Longest first — the alternation below is
#: first-match, so `token` listed before `access_token` would shadow it.
#:
#: `client_id` is deliberately NOT here. It is the username half of an OAuth2
#: client-credentials pair, not the secret, and redacting it would remove the
#: only thing in a log line that says *which* API client acted — the exact
#: attribution a customer needs for audit. Redact the secret; keep the identity.
_SECRET_NAMES = (
    "client_secret",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "authorization",
    "password",
    "passwd",
    "token",
    "secret",
)

#: `name=value`, `name: value`, `"name": "value"`.
#:
#: The lookbehind is load-bearing. Without it, `secret` matched inside
#: `client_secret` (producing a half-redacted mess) and `key` matched inside
#: `monkey=1`, corrupting unrelated lines. An unanchored pattern that quietly
#: mangles good data is the same failure as an unanchored `rx="7"` matching
#: `stroke-width`.
#: The negative lookahead on the value is not cosmetic. Without it,
#: ``Authorization: Bearer <secret>`` matched as name=`authorization`,
#: separator=`: `, value=`Bearer` — so the filter dutifully replaced the word
#: "Bearer" and published the token. Caught by running the patterns against
#: every form we emit rather than reading them and deciding they looked right.
_ASSIGNMENT = re.compile(
    r'(?<![\w-])(' + "|".join(_SECRET_NAMES) + r')'   # 1: the name
    r'("?\s*[:=]\s*"?)'                               # 2: the separator
    r'(?!(?:Bearer|Basic)\b)'                         #    ...but not a scheme
    r'([^\s",}\]]+)',                                 # 3: the value
    re.IGNORECASE,
)

#: HTTP auth headers, where the credential follows a scheme rather than a name.
#: Applied BEFORE _ASSIGNMENT — see the note above.
_SCHEME = re.compile(r'\b(Bearer|Basic)(\s+)([A-Za-z0-9+/=._\-]+)', re.IGNORECASE)


def redact(text: str) -> str:
    """Replace credential values in *text* with ``***``.

    Exposed as a function so every path that shows configuration to a human —
    logs, error messages, ``profile show`` — can use one implementation. A
    second, subtly different redactor is how a secret eventually gets printed.
    """
    if not text:
        return text
    # Scheme first: an "Authorization: Bearer x" header is both a scheme match
    # and an assignment match, and the assignment form would consume the scheme
    # keyword as the value and leave the credential behind.
    text = _SCHEME.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)
    return _ASSIGNMENT.sub(lambda m: f"{m.group(1)}{m.group(2)}{REDACTED}", text)


class SensitiveDataFilter(logging.Filter):
    """Redact credentials from log records.

    This class had two bugs, and both are worth naming, because a redaction
    filter that fails silently is more dangerous than no filter at all — it
    buys confidence without providing protection.

    1. **It only rewrote ``record.msg``.** With %-style logging the secret is in
       ``record.args``, so ``logger.info("client_secret=%s", secret)`` passed
       through untouched. Worse, rewriting the format string deleted the ``%s``,
       so the record then raised "not all arguments converted during string
       formatting" when it was emitted. The fix is to redact the *rendered*
       message and clear ``args``.

    2. **The patterns had no boundaries** — see ``_ASSIGNMENT``.

    Known limitation, stated rather than left to be discovered: values passed
    via ``extra=`` become record attributes, not part of the message, so they
    are not redacted here. No current call site puts a credential in ``extra``,
    and the JSON formatter does not emit extras — but a future one could.
    """

    def filter(self, record):
        try:
            message = record.getMessage()
        except Exception:
            # A broken format string must not stop the record from being seen.
            message = str(record.msg)

        redacted = redact(message)

        # Collapse msg+args whenever args exist, not only when something was
        # redacted: the rendering above is the only place the two are combined,
        # so leaving args in place would re-expose the raw value downstream.
        if record.args or redacted != message:
            record.msg = redacted
            record.args = ()

        return True


def setup_logging(
    level: Optional[str] = None,
    log_file: Optional[str] = None,
    max_file_size: int = 10 * 1024 * 1024,  # 10MB
    backup_count: int = 5,
    enable_console: bool = True,
    json_format: bool = False
) -> None:
    """Configure logging for server.
    
    Args:
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        log_file: Path to log file (if None, only console logging)
        max_file_size: Maximum log file size in bytes before rotation
        backup_count: Number of backup files to keep
        enable_console: Whether to enable console logging
        json_format: Whether to use JSON structured logging
    """
    # Set log level
    if level is None:
        level = os.environ.get('VECTRA_LOG_LEVEL', 'INFO')
    
    log_level = getattr(logging, level.upper(), logging.INFO)
    
    # Create root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    
    # Clear existing handlers
    root_logger.handlers.clear()
    
    # Create formatter
    if json_format:
        class JSONFormatter(logging.Formatter):
            def format(self, record):
                log_entry = {
                    'timestamp': datetime.datetime.fromtimestamp(record.created).isoformat(),
                    'level': record.levelname,
                    'logger': record.name,
                    'message': record.getMessage(),
                    'module': record.module,
                    'function': record.funcName,
                    'line': record.lineno,
                }
                if hasattr(record, 'exc_info') and record.exc_info:
                    log_entry['exception'] = self.formatException(record.exc_info)
                return json.dumps(log_entry)
        
        formatter = JSONFormatter()
    else:
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
    
    # Add sensitive data filter
    sensitive_filter = SensitiveDataFilter()
    
    # Console handler
    if enable_console:
        console_handler = logging.StreamHandler()
        console_handler.setLevel(log_level)
        console_handler.setFormatter(formatter)
        console_handler.addFilter(sensitive_filter)
        root_logger.addHandler(console_handler)
    
    # File handler with rotation
    if log_file:
        # Check log directory exists
        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
        
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=max_file_size,
            backupCount=backup_count
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(formatter)
        file_handler.addFilter(sensitive_filter)
        root_logger.addHandler(file_handler)
    
    # Set specific logger levels for high volume libraries
    logging.getLogger('httpx').setLevel(logging.WARNING)
    logging.getLogger('httpcore').setLevel(logging.WARNING)
    logging.getLogger('uvicorn.access').setLevel(logging.WARNING)


def get_logger(name: str, level: Optional[str] = None) -> logging.Logger:
    """
    Get a logger instance with optional custom level.
    
    Args:
        name: Logger name (typically __name__)
        level: Optional custom log level for this logger
        
    Returns:
        Logger instance
    """
    logger = logging.getLogger(name)
    
    if level:
        log_level = getattr(logging, level.upper(), logging.INFO)
        logger.setLevel(log_level)
    
    return logger


def configure_debug_logging():
    """Enable debug logging for troubleshooting."""
    logging.getLogger().setLevel(logging.DEBUG)
    for handler in logging.getLogger().handlers:
        handler.setLevel(logging.DEBUG)
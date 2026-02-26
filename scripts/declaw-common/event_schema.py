"""
DeClaw Security Event Schema — Python implementation.

Mirrors the TypeScript schema in src/lib/declaw-events.ts.
Used by all DeClaw Python tools to write structured audit events
to ~/.declaw/audit.jsonl.

See docs/adr/004-unified-observability.md for rationale.
"""

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

# ---------------------------------------------------------------------------
# Schema version — must match TypeScript DeclawSecurityEvent.version
# ---------------------------------------------------------------------------

SCHEMA_VERSION = 1


# ---------------------------------------------------------------------------
# Event builder
# ---------------------------------------------------------------------------


def create_event(
    source: str,
    category: str,
    severity: str,
    detail: Dict[str, Any],
    outcome: str = "success",
    agent_id: Optional[str] = None,
    session_id: Optional[str] = None,
    correlation_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Build a DeClaw security event conforming to the unified schema."""
    event: Dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": SCHEMA_VERSION,
        "source": source,
        "category": category,
        "severity": severity,
        "detail": detail,
        "outcome": outcome,
        "user": os.environ.get("USER", os.environ.get("USERNAME", "unknown")),
        "pid": os.getpid(),
    }
    if agent_id:
        event["agentId"] = agent_id
    if session_id:
        event["sessionId"] = session_id
    if correlation_id:
        event["correlationId"] = correlation_id
    return event


# ---------------------------------------------------------------------------
# Audit file writer
# ---------------------------------------------------------------------------

DECLAW_DIR = Path.home() / ".declaw"
DEFAULT_AUDIT_PATH = DECLAW_DIR / "audit.jsonl"


def write_audit_event(event: Dict[str, Any], audit_path: Optional[Path] = None) -> None:
    """Append a single event to the audit JSONL file.

    Creates ~/.declaw/ with 0o700 permissions if it doesn't exist.
    The file is opened in append mode; writes under PIPE_BUF (4096 bytes)
    are atomic on POSIX, so no locking is needed.
    """
    target = audit_path or DEFAULT_AUDIT_PATH
    try:
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        line = json.dumps(event, separators=(",", ":")) + "\n"
        with open(target, "a", encoding="utf-8") as f:
            f.write(line)
        # Ensure restrictive permissions on the audit file
        target.chmod(0o600)
    except OSError:
        # Audit logging is best-effort — don't crash the tool
        pass


def emit_event(
    source: str,
    category: str,
    severity: str,
    detail: Dict[str, Any],
    outcome: str = "success",
    audit_path: Optional[Path] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Create and write a DeClaw security event in one call."""
    event = create_event(source, category, severity, detail, outcome, **kwargs)
    write_audit_event(event, audit_path)
    return event

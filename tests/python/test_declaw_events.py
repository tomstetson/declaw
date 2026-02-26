"""
Tests for the shared DeClaw event schema (scripts/declaw-common/event_schema.py).

We test:
- Event creation with required and optional fields
- Schema version consistency
- Audit file writing and format
- Permissions on created files/directories
"""

import json
import os
import stat
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def event_schema_mod(declaw_common_mod):
    """Return the event_schema module."""
    return declaw_common_mod


@pytest.fixture()
def declaw_common_mod():
    """Import the event_schema module from scripts/declaw-common/."""
    import importlib.util

    script_path = (
        Path(__file__).resolve().parent.parent.parent
        / "scripts"
        / "declaw-common"
        / "event_schema.py"
    )
    spec = importlib.util.spec_from_file_location("event_schema", script_path)
    assert spec is not None
    mod = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture()
def audit_file(tmp_path):
    """Return a temporary audit file path."""
    return tmp_path / "audit.jsonl"


# ---------------------------------------------------------------------------
# create_event
# ---------------------------------------------------------------------------


class TestCreateEvent:
    def test_creates_event_with_required_fields(self, event_schema_mod):
        event = event_schema_mod.create_event(
            source="declaw-secrets",
            category="secret.access",
            severity="info",
            detail={"key": "API_KEY"},
        )

        assert event["version"] == 1
        assert event["source"] == "declaw-secrets"
        assert event["category"] == "secret.access"
        assert event["severity"] == "info"
        assert event["detail"] == {"key": "API_KEY"}
        assert event["outcome"] == "success"
        assert "timestamp" in event
        assert "pid" in event
        assert "user" in event

    def test_creates_event_with_optional_fields(self, event_schema_mod):
        event = event_schema_mod.create_event(
            source="declaw-monitor",
            category="monitor.detection",
            severity="critical",
            detail={"pattern": "REVERSE_SHELL"},
            outcome="denied",
            agent_id="agent-42",
            session_id="sess-abc",
            correlation_id="corr-xyz",
        )

        assert event["agentId"] == "agent-42"
        assert event["sessionId"] == "sess-abc"
        assert event["correlationId"] == "corr-xyz"
        assert event["outcome"] == "denied"

    def test_omits_none_optional_fields(self, event_schema_mod):
        event = event_schema_mod.create_event(
            source="declaw-doctor",
            category="config.check",
            severity="low",
            detail={"checkId": "L1"},
        )

        assert "agentId" not in event
        assert "sessionId" not in event
        assert "correlationId" not in event

    def test_timestamp_is_iso8601(self, event_schema_mod):
        event = event_schema_mod.create_event(
            source="declaw-secrets",
            category="secret.access",
            severity="info",
            detail={},
        )

        # ISO 8601 with timezone
        ts = event["timestamp"]
        assert "T" in ts
        assert ts.endswith("+00:00") or ts.endswith("Z")

    def test_schema_version_is_1(self, event_schema_mod):
        assert event_schema_mod.SCHEMA_VERSION == 1

    def test_pid_matches_current_process(self, event_schema_mod):
        event = event_schema_mod.create_event(
            source="declaw-secrets",
            category="secret.access",
            severity="info",
            detail={},
        )
        assert event["pid"] == os.getpid()


# ---------------------------------------------------------------------------
# write_audit_event
# ---------------------------------------------------------------------------


class TestWriteAuditEvent:
    def test_writes_jsonl_to_file(self, event_schema_mod, audit_file):
        event = event_schema_mod.create_event(
            source="declaw-secrets",
            category="secret.access",
            severity="info",
            detail={"key": "API_KEY"},
        )
        event_schema_mod.write_audit_event(event, audit_file)

        content = audit_file.read_text()
        lines = content.strip().split("\n")
        assert len(lines) == 1

        parsed = json.loads(lines[0])
        assert parsed["source"] == "declaw-secrets"
        assert parsed["detail"]["key"] == "API_KEY"

    def test_appends_multiple_events(self, event_schema_mod, audit_file):
        for key in ["KEY_A", "KEY_B", "KEY_C"]:
            event = event_schema_mod.create_event(
                source="declaw-secrets",
                category="secret.access",
                severity="info",
                detail={"key": key},
            )
            event_schema_mod.write_audit_event(event, audit_file)

        lines = audit_file.read_text().strip().split("\n")
        assert len(lines) == 3

    def test_creates_parent_directory(self, event_schema_mod, tmp_path):
        nested_path = tmp_path / "nested" / "deep" / "audit.jsonl"
        event = event_schema_mod.create_event(
            source="declaw-secrets",
            category="secret.access",
            severity="info",
            detail={},
        )
        event_schema_mod.write_audit_event(event, nested_path)
        assert nested_path.exists()

    def test_does_not_throw_on_unwritable_path(self, event_schema_mod):
        event = event_schema_mod.create_event(
            source="declaw-secrets",
            category="secret.access",
            severity="info",
            detail={},
        )
        # Should not raise — audit logging is best-effort
        event_schema_mod.write_audit_event(event, Path("/proc/nonexistent/audit.jsonl"))

    def test_audit_file_has_600_permissions(self, event_schema_mod, audit_file):
        event = event_schema_mod.create_event(
            source="declaw-secrets",
            category="secret.access",
            severity="info",
            detail={},
        )
        event_schema_mod.write_audit_event(event, audit_file)

        perms = stat.S_IMODE(audit_file.stat().st_mode)
        assert perms == 0o600


# ---------------------------------------------------------------------------
# emit_event (create + write in one call)
# ---------------------------------------------------------------------------


class TestEmitEvent:
    def test_creates_and_writes_in_one_call(self, event_schema_mod, audit_file):
        result = event_schema_mod.emit_event(
            source="declaw-monitor",
            category="monitor.detection",
            severity="critical",
            detail={"pattern": "ENV_ACCESS"},
            audit_path=audit_file,
        )

        # Returns the event
        assert result["source"] == "declaw-monitor"
        assert result["category"] == "monitor.detection"

        # Wrote to file
        content = audit_file.read_text()
        parsed = json.loads(content.strip())
        assert parsed["detail"]["pattern"] == "ENV_ACCESS"

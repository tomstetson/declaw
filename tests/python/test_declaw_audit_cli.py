"""
Tests for declaw-audit -- compliance query and export CLI.

We test:
- Event reading and filtering (category, severity, source, since, limit)
- Duration parsing (hours, days, minutes, weeks, invalid)
- Query output (table and JSON modes)
- Export output (JSON and CSV formats)
- Stats command
- Edge cases (empty file, missing file, malformed lines)
"""

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

# ---------------------------------------------------------------------------
# Test data helpers
# ---------------------------------------------------------------------------


def _write_events(path: Path, events: list):
    """Write events as JSONL to a temp file."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        for event in events:
            f.write(json.dumps(event) + "\n")


def _make_event(
    category="policy.deny",
    severity="high",
    source="declaw-gateway",
    outcome="denied",
    timestamp=None,
    detail=None,
):
    now = timestamp or datetime.now(timezone.utc).isoformat()
    return {
        "timestamp": now,
        "version": 1,
        "source": source,
        "category": category,
        "severity": severity,
        "detail": detail or {"binary": "curl"},
        "outcome": outcome,
        "user": "test",
        "pid": 1234,
    }


# ---------------------------------------------------------------------------
# Duration parsing
# ---------------------------------------------------------------------------


class TestDurationParsing:
    def test_parses_hours(self, declaw_audit_mod):
        td = declaw_audit_mod.parse_duration("24h")
        assert td == timedelta(hours=24)

    def test_parses_days(self, declaw_audit_mod):
        td = declaw_audit_mod.parse_duration("7d")
        assert td == timedelta(days=7)

    def test_parses_minutes(self, declaw_audit_mod):
        td = declaw_audit_mod.parse_duration("30m")
        assert td == timedelta(minutes=30)

    def test_parses_weeks(self, declaw_audit_mod):
        td = declaw_audit_mod.parse_duration("2w")
        assert td == timedelta(weeks=2)

    def test_parses_seconds(self, declaw_audit_mod):
        td = declaw_audit_mod.parse_duration("60s")
        assert td == timedelta(seconds=60)

    def test_rejects_invalid_format(self, declaw_audit_mod):
        with pytest.raises(ValueError, match="Invalid duration"):
            declaw_audit_mod.parse_duration("abc")

    def test_rejects_no_unit(self, declaw_audit_mod):
        with pytest.raises(ValueError, match="Invalid duration"):
            declaw_audit_mod.parse_duration("24")


# ---------------------------------------------------------------------------
# Event reading
# ---------------------------------------------------------------------------


class TestReadEvents:
    def test_reads_all_events(self, declaw_audit_mod, tmp_path):
        audit_path = tmp_path / "audit.jsonl"
        events = [_make_event(), _make_event(category="secret.access")]
        _write_events(audit_path, events)

        result = declaw_audit_mod.read_events(audit_path)
        assert len(result) == 2

    def test_handles_missing_file(self, declaw_audit_mod, tmp_path):
        result = declaw_audit_mod.read_events(tmp_path / "nonexistent.jsonl")
        assert result == []

    def test_handles_empty_file(self, declaw_audit_mod, tmp_path):
        audit_path = tmp_path / "audit.jsonl"
        audit_path.write_text("")
        result = declaw_audit_mod.read_events(audit_path)
        assert result == []

    def test_skips_malformed_lines(self, declaw_audit_mod, tmp_path):
        audit_path = tmp_path / "audit.jsonl"
        audit_path.write_text(
            json.dumps(_make_event()) + "\n"
            + "not json\n"
            + json.dumps(_make_event()) + "\n"
        )
        result = declaw_audit_mod.read_events(audit_path)
        assert len(result) == 2


# ---------------------------------------------------------------------------
# Filtering
# ---------------------------------------------------------------------------


class TestFilterEvents:
    def test_filters_by_category(self, declaw_audit_mod):
        events = [
            _make_event(category="policy.deny"),
            _make_event(category="secret.access"),
            _make_event(category="policy.deny"),
        ]
        result = declaw_audit_mod.filter_events(events, categories=["policy.deny"])
        assert len(result) == 2

    def test_filters_by_severity(self, declaw_audit_mod):
        events = [
            _make_event(severity="high"),
            _make_event(severity="low"),
            _make_event(severity="critical"),
        ]
        result = declaw_audit_mod.filter_events(events, severities=["high", "critical"])
        assert len(result) == 2

    def test_filters_by_source(self, declaw_audit_mod):
        events = [
            _make_event(source="declaw-gateway"),
            _make_event(source="declaw-monitor"),
        ]
        result = declaw_audit_mod.filter_events(events, sources=["declaw-monitor"])
        assert len(result) == 1
        assert result[0]["source"] == "declaw-monitor"

    def test_filters_by_since(self, declaw_audit_mod):
        old = "2025-01-01T00:00:00+00:00"
        new = "2026-01-01T00:00:00+00:00"
        events = [_make_event(timestamp=old), _make_event(timestamp=new)]
        since = datetime(2025, 6, 1, tzinfo=timezone.utc)
        result = declaw_audit_mod.filter_events(events, since=since)
        assert len(result) == 1
        assert result[0]["timestamp"] == new

    def test_no_filters_returns_all(self, declaw_audit_mod):
        events = [_make_event(), _make_event(), _make_event()]
        result = declaw_audit_mod.filter_events(events)
        assert len(result) == 3


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------


class TestCsvExport:
    def test_csv_has_correct_headers(self, declaw_audit_mod):
        events = [_make_event()]
        csv_output = declaw_audit_mod._export_csv(events)
        first_line = csv_output.split("\n")[0]
        assert "timestamp" in first_line
        assert "category" in first_line
        assert "severity" in first_line
        assert "detail" in first_line

    def test_csv_serializes_detail_as_json(self, declaw_audit_mod):
        events = [_make_event(detail={"key": "val"})]
        csv_output = declaw_audit_mod._export_csv(events)
        lines = csv_output.strip().split("\n")
        assert len(lines) == 2  # header + 1 data row
        # Detail should be JSON string
        assert '"key"' in lines[1]

    def test_csv_handles_empty_events(self, declaw_audit_mod):
        csv_output = declaw_audit_mod._export_csv([])
        lines = csv_output.strip().split("\n")
        assert len(lines) == 1  # header only


# ---------------------------------------------------------------------------
# Detail summary formatting
# ---------------------------------------------------------------------------


class TestFormatDetailSummary:
    def test_policy_deny_shows_binary(self, declaw_audit_mod):
        event = _make_event(category="policy.deny", detail={"binary": "curl"})
        summary = declaw_audit_mod.format_detail_summary(event)
        assert "curl" in summary

    def test_secret_access_shows_key(self, declaw_audit_mod):
        event = _make_event(category="secret.access", detail={"key": "API_KEY"})
        summary = declaw_audit_mod.format_detail_summary(event)
        assert "API_KEY" in summary

    def test_config_check_shows_id(self, declaw_audit_mod):
        event = _make_event(
            category="config.check",
            detail={"checkId": "C1", "title": "Gateway token"}
        )
        summary = declaw_audit_mod.format_detail_summary(event)
        assert "C1" in summary

    def test_unknown_category_falls_back_to_json(self, declaw_audit_mod):
        event = _make_event(category="unknown.new", detail={"foo": "bar"})
        summary = declaw_audit_mod.format_detail_summary(event)
        assert "foo" in summary

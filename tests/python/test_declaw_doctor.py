"""
Tests for declaw-doctor -- OpenClaw config security auditor.

We test:
- Each of the 10 security checks against known-bad and known-good configs
- Check severity levels (CRITICAL, HIGH, MEDIUM, LOW)
- Auto-fix creates backups
- --dry-run doesn't modify config
- Config with all issues vs config with no issues
"""

import json
import shutil
from pathlib import Path
from unittest.mock import patch

import pytest


# ---------------------------------------------------------------------------
# Individual check methods (against known-bad configs)
# ---------------------------------------------------------------------------


class TestGatewayTokenCheck:
    """C1: Gateway auth token missing or too short."""

    def test_missing_token_detected(self, declaw_doctor_mod):
        config = {"gateway": {"auth": {}}}
        auditor = self._make_auditor(declaw_doctor_mod, config)
        result = auditor._check_gateway_token(config)
        assert result is not None
        assert "not set" in result

    def test_short_token_detected(self, declaw_doctor_mod):
        config = {"gateway": {"auth": {"token": "tooshort"}}}
        auditor = self._make_auditor(declaw_doctor_mod, config)
        result = auditor._check_gateway_token(config)
        assert result is not None
        assert "too short" in result

    def test_valid_token_passes(self, declaw_doctor_mod, secure_config):
        auditor = self._make_auditor(declaw_doctor_mod, secure_config)
        result = auditor._check_gateway_token(secure_config)
        assert result is None

    def test_severity_is_critical(self, declaw_doctor_mod):
        checks = self._get_check_by_id(declaw_doctor_mod, "C1")
        assert checks.severity == "CRITICAL"

    def _make_auditor(self, mod, config):
        auditor = mod.ConfigAuditor.__new__(mod.ConfigAuditor)
        auditor.config = config
        auditor.verbose = False
        auditor.issues = []
        auditor.warnings = []
        auditor.info = []
        return auditor

    def _get_check_by_id(self, mod, check_id):
        auditor = self._make_auditor(mod, {})
        for check in auditor._get_checks():
            if check.id == check_id:
                return check
        pytest.fail(f"Check {check_id} not found")


class TestEnvVarsCheck:
    """C2: API keys stored in environment variables."""

    def test_api_key_in_env_detected(self, declaw_doctor_mod, insecure_config):
        auditor = _make_auditor(declaw_doctor_mod, insecure_config)
        result = auditor._check_env_vars(insecure_config)
        assert result is not None
        assert "ANTHROPIC_API_KEY" in result

    def test_secret_uri_not_flagged(self, declaw_doctor_mod):
        config = {
            "agents": {
                "list": [{
                    "id": "agent1",
                    "sandbox": {"docker": {"env": {
                        "API_KEY": "secret://MY_KEY",
                    }}}
                }]
            }
        }
        auditor = _make_auditor(declaw_doctor_mod, config)
        result = auditor._check_env_vars(config)
        assert result is None

    def test_non_sensitive_env_var_not_flagged(self, declaw_doctor_mod):
        config = {
            "agents": {
                "list": [{
                    "id": "agent1",
                    "sandbox": {"docker": {"env": {
                        "LOG_LEVEL": "debug",
                        "WORKSPACE": "/app",
                    }}}
                }]
            }
        }
        auditor = _make_auditor(declaw_doctor_mod, config)
        result = auditor._check_env_vars(config)
        assert result is None

    def test_severity_is_critical(self, declaw_doctor_mod):
        check = _get_check_by_id(declaw_doctor_mod, "C2")
        assert check.severity == "CRITICAL"


class TestSandboxEnabledCheck:
    """C3: Sandbox disabled for one or more agents."""

    def test_sandbox_off_detected(self, declaw_doctor_mod, insecure_config):
        auditor = _make_auditor(declaw_doctor_mod, insecure_config)
        result = auditor._check_sandbox_enabled(insecure_config)
        assert result is not None
        assert "sandbox=off" in result

    def test_sandbox_all_passes(self, declaw_doctor_mod, secure_config):
        auditor = _make_auditor(declaw_doctor_mod, secure_config)
        result = auditor._check_sandbox_enabled(secure_config)
        assert result is None


class TestDangerousToolsCheck:
    """H1: Dangerous tools allowed."""

    def test_gateway_tool_detected(self, declaw_doctor_mod, insecure_config):
        auditor = _make_auditor(declaw_doctor_mod, insecure_config)
        result = auditor._check_dangerous_tools(insecure_config)
        assert result is not None
        assert "gateway" in result

    def test_sessions_send_detected(self, declaw_doctor_mod, insecure_config):
        auditor = _make_auditor(declaw_doctor_mod, insecure_config)
        result = auditor._check_dangerous_tools(insecure_config)
        assert "sessions_send" in result

    def test_safe_tools_pass(self, declaw_doctor_mod, secure_config):
        auditor = _make_auditor(declaw_doctor_mod, secure_config)
        result = auditor._check_dangerous_tools(secure_config)
        assert result is None

    def test_severity_is_high(self, declaw_doctor_mod):
        check = _get_check_by_id(declaw_doctor_mod, "H1")
        assert check.severity == "HIGH"


class TestExecApprovalsCheck:
    """H2: Exec approvals disabled."""

    def test_disabled_detected(self, declaw_doctor_mod, insecure_config):
        auditor = _make_auditor(declaw_doctor_mod, insecure_config)
        result = auditor._check_exec_approvals(insecure_config)
        assert result is not None
        assert "disabled" in result

    def test_enabled_passes(self, declaw_doctor_mod, secure_config):
        auditor = _make_auditor(declaw_doctor_mod, secure_config)
        result = auditor._check_exec_approvals(secure_config)
        assert result is None


class TestReadOnlyRootCheck:
    """H3: readOnlyRoot disabled."""

    def test_writable_root_detected(self, declaw_doctor_mod, insecure_config):
        auditor = _make_auditor(declaw_doctor_mod, insecure_config)
        result = auditor._check_readonly_root(insecure_config)
        assert result is not None
        assert "writable" in result

    def test_readonly_root_passes(self, declaw_doctor_mod, secure_config):
        auditor = _make_auditor(declaw_doctor_mod, secure_config)
        result = auditor._check_readonly_root(secure_config)
        assert result is None


class TestContextPruningCheck:
    """M1: Context pruning not enabled."""

    def test_pruning_off_detected(self, declaw_doctor_mod, insecure_config):
        auditor = _make_auditor(declaw_doctor_mod, insecure_config)
        result = auditor._check_context_pruning(insecure_config)
        assert result is not None
        assert "disabled" in result

    def test_pruning_enabled_passes(self, declaw_doctor_mod, secure_config):
        auditor = _make_auditor(declaw_doctor_mod, secure_config)
        result = auditor._check_context_pruning(secure_config)
        assert result is None

    def test_severity_is_medium(self, declaw_doctor_mod):
        check = _get_check_by_id(declaw_doctor_mod, "M1")
        assert check.severity == "MEDIUM"


class TestGatewayBindCheck:
    """M2: Gateway bound to non-loopback without TLS."""

    def test_nonloopback_without_tls_detected(self, declaw_doctor_mod, insecure_config):
        auditor = _make_auditor(declaw_doctor_mod, insecure_config)
        result = auditor._check_gateway_bind(insecure_config)
        assert result is not None
        assert "0.0.0.0" in result

    def test_loopback_passes(self, declaw_doctor_mod, secure_config):
        auditor = _make_auditor(declaw_doctor_mod, secure_config)
        result = auditor._check_gateway_bind(secure_config)
        assert result is None

    def test_tailscale_mode_passes(self, declaw_doctor_mod):
        config = {"gateway": {"bind": "0.0.0.0", "mode": "tailscale"}}
        auditor = _make_auditor(declaw_doctor_mod, config)
        result = auditor._check_gateway_bind(config)
        assert result is None


class TestCapDropCheck:
    """M3: No capability drop configured."""

    def test_no_cap_drop_detected(self, declaw_doctor_mod, insecure_config):
        auditor = _make_auditor(declaw_doctor_mod, insecure_config)
        result = auditor._check_cap_drop(insecure_config)
        assert result is not None
        assert "ALL" in result

    def test_cap_drop_all_passes(self, declaw_doctor_mod, secure_config):
        auditor = _make_auditor(declaw_doctor_mod, secure_config)
        result = auditor._check_cap_drop(secure_config)
        assert result is None


class TestReloadModeCheck:
    """L1: Gateway reload mode may cause race conditions."""

    def test_hybrid_mode_detected(self, declaw_doctor_mod, insecure_config):
        auditor = _make_auditor(declaw_doctor_mod, insecure_config)
        result = auditor._check_reload_mode(insecure_config)
        assert result is not None
        assert "hybrid" in result

    def test_hot_mode_passes(self, declaw_doctor_mod, secure_config):
        auditor = _make_auditor(declaw_doctor_mod, secure_config)
        result = auditor._check_reload_mode(secure_config)
        assert result is None

    def test_off_mode_passes(self, declaw_doctor_mod):
        config = {"gateway": {"reload": {"mode": "off"}}}
        auditor = _make_auditor(declaw_doctor_mod, config)
        result = auditor._check_reload_mode(config)
        assert result is None

    def test_severity_is_low(self, declaw_doctor_mod):
        check = _get_check_by_id(declaw_doctor_mod, "L1")
        assert check.severity == "LOW"


class TestCommandPolicyCheck:
    """H4: No command policy configured."""

    def test_no_policy_detected(self, declaw_doctor_mod):
        config = {"tools": {"exec": {}}}
        auditor = _make_auditor(declaw_doctor_mod, config)
        result = auditor._check_command_policy(config)
        assert result is not None
        assert "No command policy" in result

    def test_denylist_policy_passes(self, declaw_doctor_mod):
        config = {"tools": {"exec": {"commandPolicy": {"mode": "denylist", "deny": ["curl"]}}}}
        auditor = _make_auditor(declaw_doctor_mod, config)
        result = auditor._check_command_policy(config)
        assert result is None

    def test_allowlist_policy_passes(self, declaw_doctor_mod):
        config = {"tools": {"exec": {"commandPolicy": {"mode": "allowlist", "allow": ["ls"]}}}}
        auditor = _make_auditor(declaw_doctor_mod, config)
        result = auditor._check_command_policy(config)
        assert result is None

    def test_per_agent_policy_passes(self, declaw_doctor_mod):
        config = {
            "agents": {"list": [{
                "id": "a1",
                "tools": {"exec": {"commandPolicy": {"mode": "denylist", "deny": ["curl"]}}}
            }]}
        }
        auditor = _make_auditor(declaw_doctor_mod, config)
        result = auditor._check_command_policy(config)
        assert result is None

    def test_off_mode_detected(self, declaw_doctor_mod):
        config = {"tools": {"exec": {"commandPolicy": {"mode": "off"}}}}
        auditor = _make_auditor(declaw_doctor_mod, config)
        result = auditor._check_command_policy(config)
        assert result is not None

    def test_empty_config_detected(self, declaw_doctor_mod):
        auditor = _make_auditor(declaw_doctor_mod, {})
        result = auditor._check_command_policy({})
        assert result is not None

    def test_severity_is_high(self, declaw_doctor_mod):
        check = _get_check_by_id(declaw_doctor_mod, "H4")
        assert check.severity == "HIGH"

    def test_is_auto_fixable(self, declaw_doctor_mod):
        check = _get_check_by_id(declaw_doctor_mod, "H4")
        assert check.fix_fn is not None

    def test_auto_fix_adds_denylist(self, declaw_doctor_mod):
        config = {}
        auditor = _make_auditor(declaw_doctor_mod, config)
        auditor._fix_command_policy(config)
        policy = config["tools"]["exec"]["commandPolicy"]
        assert policy["mode"] == "denylist"
        assert "curl" in policy["deny"]
        assert "wget" in policy["deny"]
        assert "sudo" in policy["deny"]


class TestEgressPolicyCheck:
    """H5: Sandbox network not restricted."""

    def test_network_none_passes(self, declaw_doctor_mod):
        config = {
            "agents": {"list": [{
                "id": "a1",
                "sandbox": {"docker": {"network": "none"}}
            }]}
        }
        auditor = _make_auditor(declaw_doctor_mod, config)
        result = auditor._check_egress_policy(config)
        assert result is None

    def test_bridge_without_policy_detected(self, declaw_doctor_mod):
        config = {
            "agents": {"list": [{
                "id": "a1",
                "sandbox": {"docker": {"network": "bridge"}}
            }]}
        }
        auditor = _make_auditor(declaw_doctor_mod, config)
        result = auditor._check_egress_policy(config)
        assert result is not None
        assert "without egress policy" in result

    def test_bridge_with_deny_all_passes(self, declaw_doctor_mod):
        config = {
            "agents": {"list": [{
                "id": "a1",
                "sandbox": {"docker": {
                    "network": "bridge",
                    "egressPolicy": {"mode": "deny-all"}
                }}
            }]}
        }
        auditor = _make_auditor(declaw_doctor_mod, config)
        result = auditor._check_egress_policy(config)
        assert result is None

    def test_bridge_with_restricted_passes(self, declaw_doctor_mod):
        config = {
            "agents": {"list": [{
                "id": "a1",
                "sandbox": {"docker": {
                    "network": "bridge",
                    "egressPolicy": {"mode": "restricted"}
                }}
            }]}
        }
        auditor = _make_auditor(declaw_doctor_mod, config)
        result = auditor._check_egress_policy(config)
        assert result is None

    def test_default_network_detected(self, declaw_doctor_mod):
        config = {
            "agents": {
                "defaults": {"sandbox": {"docker": {"network": "bridge"}}},
                "list": []
            }
        }
        auditor = _make_auditor(declaw_doctor_mod, config)
        result = auditor._check_egress_policy(config)
        assert result is not None
        assert "Default sandbox" in result

    def test_no_agents_passes(self, declaw_doctor_mod):
        auditor = _make_auditor(declaw_doctor_mod, {})
        result = auditor._check_egress_policy({})
        assert result is None

    def test_severity_is_high(self, declaw_doctor_mod):
        check = _get_check_by_id(declaw_doctor_mod, "H5")
        assert check.severity == "HIGH"

    def test_is_auto_fixable(self, declaw_doctor_mod):
        check = _get_check_by_id(declaw_doctor_mod, "H5")
        assert check.fix_fn is not None

    def test_auto_fix_sets_deny_all(self, declaw_doctor_mod):
        config = {
            "agents": {"list": [{
                "id": "a1",
                "sandbox": {"docker": {"network": "bridge"}}
            }]}
        }
        auditor = _make_auditor(declaw_doctor_mod, config)
        auditor._fix_egress_policy(config)
        docker = config["agents"]["list"][0]["sandbox"]["docker"]
        assert docker["egressPolicy"]["mode"] == "deny-all"
        assert docker["network"] == "none"


class TestPluginSecurityCheck:
    """M4: No plugin security scanning policy configured."""

    def test_no_policy_detected(self, declaw_doctor_mod):
        config = {}
        auditor = _make_auditor(declaw_doctor_mod, config)
        result = auditor._check_plugin_security(config)
        assert result is not None
        assert "No plugin security policy" in result

    def test_off_mode_detected(self, declaw_doctor_mod):
        config = {"plugins": {"pluginSecurity": {"mode": "off"}}}
        auditor = _make_auditor(declaw_doctor_mod, config)
        result = auditor._check_plugin_security(config)
        assert result is not None

    def test_enforce_mode_passes(self, declaw_doctor_mod):
        config = {"plugins": {"pluginSecurity": {
            "mode": "enforce",
            "blockedCapabilities": ["exec"],
        }}}
        auditor = _make_auditor(declaw_doctor_mod, config)
        result = auditor._check_plugin_security(config)
        assert result is None

    def test_warn_mode_without_capabilities_warns(self, declaw_doctor_mod):
        config = {"plugins": {"pluginSecurity": {"mode": "warn"}}}
        auditor = _make_auditor(declaw_doctor_mod, config)
        result = auditor._check_plugin_security(config)
        assert result is not None
        assert "without blocked capabilities" in result

    def test_warn_mode_with_capabilities_passes(self, declaw_doctor_mod):
        config = {"plugins": {"pluginSecurity": {
            "mode": "warn",
            "blockedCapabilities": ["exec", "network"],
        }}}
        auditor = _make_auditor(declaw_doctor_mod, config)
        result = auditor._check_plugin_security(config)
        assert result is None

    def test_empty_plugins_detected(self, declaw_doctor_mod):
        config = {"plugins": {}}
        auditor = _make_auditor(declaw_doctor_mod, config)
        result = auditor._check_plugin_security(config)
        assert result is not None

    def test_severity_is_medium(self, declaw_doctor_mod):
        check = _get_check_by_id(declaw_doctor_mod, "M4")
        assert check.severity == "MEDIUM"

    def test_is_auto_fixable(self, declaw_doctor_mod):
        check = _get_check_by_id(declaw_doctor_mod, "M4")
        assert check.fix_fn is not None

    def test_auto_fix_sets_enforce(self, declaw_doctor_mod):
        config = {}
        auditor = _make_auditor(declaw_doctor_mod, config)
        auditor._fix_plugin_security(config)
        policy = config["plugins"]["pluginSecurity"]
        assert policy["mode"] == "enforce"
        assert policy["maxCriticalFindings"] == 0
        assert "exec" in policy["blockedCapabilities"]
        assert "crypto-mining" in policy["blockedCapabilities"]
        assert "bundled" in policy["trustedOrigins"]


# ---------------------------------------------------------------------------
# Full audit runs
# ---------------------------------------------------------------------------


class TestFullAudit:
    """Test run_checks() against complete configs."""

    def test_secure_config_has_no_issues(self, declaw_doctor_mod, secure_config_file):
        auditor = declaw_doctor_mod.ConfigAuditor(secure_config_file)
        issues, warnings, info = auditor.run_checks()
        assert len(issues) == 0
        assert len(warnings) == 0
        assert len(info) == 0

    def test_insecure_config_finds_all_issues(self, declaw_doctor_mod, insecure_config_file):
        auditor = declaw_doctor_mod.ConfigAuditor(insecure_config_file)
        issues, warnings, info = auditor.run_checks()
        # Should find all critical and high issues
        assert len(issues) > 0
        # Check that critical issues include expected IDs
        issue_ids = {i["id"] for i in issues}
        assert "C1" in issue_ids  # short token
        assert "C2" in issue_ids  # API keys in env
        assert "C3" in issue_ids  # sandbox off

    def test_issue_structure_has_required_fields(self, declaw_doctor_mod, insecure_config_file):
        auditor = declaw_doctor_mod.ConfigAuditor(insecure_config_file)
        issues, warnings, info = auditor.run_checks()
        for issue in issues + warnings + info:
            assert "id" in issue
            assert "severity" in issue
            assert "title" in issue
            assert "message" in issue
            assert "fixable" in issue

    def test_check_count_is_13(self, declaw_doctor_mod, secure_config_file):
        """There should be exactly 13 security checks defined."""
        auditor = declaw_doctor_mod.ConfigAuditor(secure_config_file)
        checks = auditor._get_checks()
        assert len(checks) == 13


# ---------------------------------------------------------------------------
# Auto-fix
# ---------------------------------------------------------------------------


class TestAutoFix:
    """Test auto-fix creates backups and modifies config correctly."""

    def test_autofix_creates_backup(self, declaw_doctor_mod, insecure_config_file):
        auditor = declaw_doctor_mod.ConfigAuditor(insecure_config_file)
        auditor.auto_fix()
        auditor.save_config()

        backup = insecure_config_file.with_suffix(".json.bak")
        assert backup.exists()

        # Backup should contain original insecure config
        with open(backup) as f:
            backup_config = json.load(f)
        assert backup_config["gateway"]["auth"]["token"] == "short"

    def test_autofix_generates_strong_token(self, declaw_doctor_mod, insecure_config_file):
        auditor = declaw_doctor_mod.ConfigAuditor(insecure_config_file)
        auditor.auto_fix()

        token = auditor.config["gateway"]["auth"]["token"]
        assert len(token) >= 32

    def test_autofix_enables_sandbox(self, declaw_doctor_mod, insecure_config_file):
        auditor = declaw_doctor_mod.ConfigAuditor(insecure_config_file)
        auditor.auto_fix()

        for agent in auditor.config["agents"]["list"]:
            assert agent["sandbox"]["mode"] == "all"

    def test_autofix_removes_dangerous_tools(self, declaw_doctor_mod, insecure_config_file):
        auditor = declaw_doctor_mod.ConfigAuditor(insecure_config_file)
        auditor.auto_fix()

        dangerous = {"gateway", "sessions_send", "sessions_list", "sessions_history", "nodes"}
        for agent in auditor.config["agents"]["list"]:
            allowed = set(agent["tools"]["allow"])
            assert allowed.isdisjoint(dangerous), f"Dangerous tools still present: {allowed & dangerous}"

    def test_autofix_enables_exec_approvals(self, declaw_doctor_mod, insecure_config_file):
        auditor = declaw_doctor_mod.ConfigAuditor(insecure_config_file)
        # Patch input() since _fix_exec_approvals may prompt for Telegram ID
        with patch("builtins.input", return_value=""):
            auditor.auto_fix()

        assert auditor.config["approvals"]["exec"]["enabled"] is True

    def test_autofix_enables_readonly_root(self, declaw_doctor_mod, insecure_config_file):
        auditor = declaw_doctor_mod.ConfigAuditor(insecure_config_file)
        auditor.auto_fix()

        for agent in auditor.config["agents"]["list"]:
            assert agent["sandbox"]["docker"]["readOnlyRoot"] is True

    def test_autofix_enables_context_pruning(self, declaw_doctor_mod, insecure_config_file):
        auditor = declaw_doctor_mod.ConfigAuditor(insecure_config_file)
        auditor.auto_fix()

        assert auditor.config["agents"]["contextPruning"]["mode"] != "off"

    def test_autofix_drops_all_caps(self, declaw_doctor_mod, insecure_config_file):
        auditor = declaw_doctor_mod.ConfigAuditor(insecure_config_file)
        auditor.auto_fix()

        for agent in auditor.config["agents"]["list"]:
            assert "ALL" in agent["sandbox"]["docker"]["capDrop"]

    def test_autofix_sets_hot_reload(self, declaw_doctor_mod, insecure_config_file):
        auditor = declaw_doctor_mod.ConfigAuditor(insecure_config_file)
        auditor.auto_fix()

        assert auditor.config["gateway"]["reload"]["mode"] == "hot"

    def test_dry_run_does_not_modify_config_or_call_fix_fns(self, declaw_doctor_mod, insecure_config_file):
        """auto_fix(dry_run=True) counts fixable issues without modifying config
        or triggering side effects like interactive prompts."""
        auditor = declaw_doctor_mod.ConfigAuditor(insecure_config_file)
        original_config = json.loads(json.dumps(auditor.config))

        # dry_run=True should NOT call input() or any fix function
        count = auditor.auto_fix(dry_run=True)

        assert count > 0, "Should detect fixable issues"
        assert auditor.config == original_config, "Config must not be modified in dry-run"
        # File on disk also unchanged
        assert insecure_config_file.read_text() == json.dumps(original_config, indent=2)

    def test_dry_run_does_not_prompt_for_input(self, declaw_doctor_mod, insecure_config_file):
        """dry_run=True must never call input() — the old code would block on stdin."""
        auditor = declaw_doctor_mod.ConfigAuditor(insecure_config_file)

        with patch("builtins.input") as mock_input:
            auditor.auto_fix(dry_run=True)
            mock_input.assert_not_called()

    def test_autofix_returns_count(self, declaw_doctor_mod, insecure_config_file):
        auditor = declaw_doctor_mod.ConfigAuditor(insecure_config_file)
        with patch("builtins.input", return_value=""):
            count = auditor.auto_fix()
        # Should fix most issues (C2 env vars is not fixable)
        assert count > 0


# ---------------------------------------------------------------------------
# Severity ordering
# ---------------------------------------------------------------------------


class TestSeverityOrdering:
    """ConfigAuditor.SEVERITY_ORDER ranks CRITICAL < HIGH < MEDIUM < LOW."""

    def test_critical_ranks_highest(self, declaw_doctor_mod):
        order = declaw_doctor_mod.ConfigAuditor.SEVERITY_ORDER
        assert order["CRITICAL"] < order["HIGH"]
        assert order["HIGH"] < order["MEDIUM"]
        assert order["MEDIUM"] < order["LOW"]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_auditor(mod, config):
    """Create a ConfigAuditor without reading from disk."""
    auditor = mod.ConfigAuditor.__new__(mod.ConfigAuditor)
    auditor.config = config
    auditor.config_path = Path("/dev/null")
    auditor.verbose = False
    auditor.issues = []
    auditor.warnings = []
    auditor.info = []
    return auditor


def _get_check_by_id(mod, check_id):
    """Retrieve a SecurityCheck by its ID."""
    auditor = _make_auditor(mod, {})
    for check in auditor._get_checks():
        if check.id == check_id:
            return check
    pytest.fail(f"Check {check_id} not found")

"""
Tests for declaw-secrets -- multi-provider secrets manager.

We test:
- SecretProvider base class interface
- EnvFileProvider: set/get/list with temp files, edge cases
- Auto-detection priority logic (mocked is_available)
- CLI argument parsing
- Audit log format (JSONL with required fields)

We do NOT test real keychain/vault/bitwarden/1password (they need real credentials
and external services). Those providers are tested only for is_available() behavior
via mocking subprocess calls.
"""

import json
import os
import stat
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


# ---------------------------------------------------------------------------
# SecretProvider base class
# ---------------------------------------------------------------------------


class TestSecretProviderInterface:
    """SecretProvider is an abstract base -- all methods raise NotImplementedError."""

    def test_get_raises(self, declaw_secrets_mod):
        provider = declaw_secrets_mod.SecretProvider()
        with pytest.raises(NotImplementedError):
            provider.get("any_key")

    def test_set_raises(self, declaw_secrets_mod):
        provider = declaw_secrets_mod.SecretProvider()
        with pytest.raises(NotImplementedError):
            provider.set("any_key", "any_value")

    def test_list_keys_raises(self, declaw_secrets_mod):
        provider = declaw_secrets_mod.SecretProvider()
        with pytest.raises(NotImplementedError):
            provider.list_keys()

    def test_is_available_raises(self, declaw_secrets_mod):
        provider = declaw_secrets_mod.SecretProvider()
        with pytest.raises(NotImplementedError):
            provider.is_available()


# ---------------------------------------------------------------------------
# EnvFileProvider
# ---------------------------------------------------------------------------


class TestEnvFileProvider:
    """EnvFileProvider reads/writes a simple KEY="value" file."""

    @pytest.fixture
    def env_provider(self, declaw_secrets_mod, tmp_path):
        """Create an EnvFileProvider pointing at a temp directory."""
        provider = declaw_secrets_mod.EnvFileProvider()
        provider.env_file = tmp_path / "secrets.env"
        return provider

    def test_is_available_always_true(self, env_provider):
        assert env_provider.is_available() is True

    def test_get_missing_file_returns_none(self, env_provider):
        """When the env file doesn't exist, get() returns None."""
        assert env_provider.get("NONEXISTENT") is None

    def test_set_creates_file_and_get_retrieves(self, env_provider):
        env_provider.set("MY_KEY", "my_value")
        assert env_provider.env_file.exists()
        assert env_provider.get("MY_KEY") == "my_value"

    def test_set_updates_existing_key(self, env_provider):
        env_provider.set("KEY1", "old")
        env_provider.set("KEY1", "new")
        assert env_provider.get("KEY1") == "new"

    def test_set_preserves_other_keys(self, env_provider):
        env_provider.set("KEY_A", "aaa")
        env_provider.set("KEY_B", "bbb")
        assert env_provider.get("KEY_A") == "aaa"
        assert env_provider.get("KEY_B") == "bbb"

    def test_set_creates_parent_directories(self, declaw_secrets_mod, tmp_path):
        provider = declaw_secrets_mod.EnvFileProvider()
        provider.env_file = tmp_path / "nested" / "dir" / "secrets.env"
        provider.set("DEEP_KEY", "deep_value")
        assert provider.get("DEEP_KEY") == "deep_value"

    def test_set_permissions_600(self, env_provider):
        """File should be chmod 600 (owner read/write only)."""
        env_provider.set("KEY", "val")
        mode = env_provider.env_file.stat().st_mode
        assert stat.S_IMODE(mode) == 0o600

    def test_list_keys_empty_file(self, env_provider):
        assert env_provider.list_keys() == []

    def test_list_keys_returns_all_keys(self, env_provider):
        env_provider.set("ALPHA", "1")
        env_provider.set("BETA", "2")
        keys = env_provider.list_keys()
        assert "ALPHA" in keys
        assert "BETA" in keys
        assert len(keys) == 2

    def test_get_ignores_comments_and_blank_lines(self, env_provider):
        """Comments and blank lines in the env file should be skipped."""
        env_provider.env_file.parent.mkdir(parents=True, exist_ok=True)
        env_provider.env_file.write_text(
            '# This is a comment\n'
            '\n'
            'REAL_KEY="real_value"\n'
            '# Another comment\n'
        )
        assert env_provider.get("REAL_KEY") == "real_value"
        assert env_provider.get("# This is a comment") is None

    def test_get_strips_quotes(self, env_provider):
        """Values wrapped in single or double quotes should be stripped."""
        env_provider.env_file.parent.mkdir(parents=True, exist_ok=True)
        env_provider.env_file.write_text(
            'DOUBLE="double_val"\n'
            "SINGLE='single_val'\n"
        )
        assert env_provider.get("DOUBLE") == "double_val"
        assert env_provider.get("SINGLE") == "single_val"

    def test_get_handles_equals_in_value(self, env_provider):
        """Values containing = should not be split incorrectly."""
        env_provider.env_file.parent.mkdir(parents=True, exist_ok=True)
        env_provider.env_file.write_text('BASE64="dGVzdA=="\n')
        assert env_provider.get("BASE64") == "dGVzdA=="


# ---------------------------------------------------------------------------
# Auto-detection priority
# ---------------------------------------------------------------------------


class TestAutoDetection:
    """SecretsManager._auto_detect_provider() picks the first available provider
    in priority order: keychain > vault > bitwarden > 1password > env."""

    def test_keychain_wins_when_available(self, declaw_secrets_mod, tmp_path):
        """If keychain is available, it should be chosen first."""
        with patch.object(declaw_secrets_mod.KeychainProvider, "is_available", return_value=True):
            mgr = declaw_secrets_mod.SecretsManager.__new__(declaw_secrets_mod.SecretsManager)
            mgr.config = {}
            mgr.config_file = tmp_path / "config.json"
            result = mgr._auto_detect_provider()
            assert result == "keychain"

    def test_vault_chosen_when_keychain_unavailable(self, declaw_secrets_mod, tmp_path):
        with patch.object(declaw_secrets_mod.KeychainProvider, "is_available", return_value=False), \
             patch.object(declaw_secrets_mod.VaultProvider, "is_available", return_value=True):
            mgr = declaw_secrets_mod.SecretsManager.__new__(declaw_secrets_mod.SecretsManager)
            mgr.config = {}
            mgr.config_file = tmp_path / "config.json"
            result = mgr._auto_detect_provider()
            assert result == "vault"

    def test_bitwarden_chosen_when_keychain_vault_unavailable(self, declaw_secrets_mod, tmp_path):
        with patch.object(declaw_secrets_mod.KeychainProvider, "is_available", return_value=False), \
             patch.object(declaw_secrets_mod.VaultProvider, "is_available", return_value=False), \
             patch.object(declaw_secrets_mod.BitwardenProvider, "is_available", return_value=True):
            mgr = declaw_secrets_mod.SecretsManager.__new__(declaw_secrets_mod.SecretsManager)
            mgr.config = {}
            mgr.config_file = tmp_path / "config.json"
            result = mgr._auto_detect_provider()
            assert result == "bitwarden"

    def test_1password_chosen_when_others_unavailable(self, declaw_secrets_mod, tmp_path):
        with patch.object(declaw_secrets_mod.KeychainProvider, "is_available", return_value=False), \
             patch.object(declaw_secrets_mod.VaultProvider, "is_available", return_value=False), \
             patch.object(declaw_secrets_mod.BitwardenProvider, "is_available", return_value=False), \
             patch.object(declaw_secrets_mod.OnePasswordProvider, "is_available", return_value=True):
            mgr = declaw_secrets_mod.SecretsManager.__new__(declaw_secrets_mod.SecretsManager)
            mgr.config = {}
            mgr.config_file = tmp_path / "config.json"
            result = mgr._auto_detect_provider()
            assert result == "1password"

    def test_env_fallback_when_nothing_available(self, declaw_secrets_mod, tmp_path):
        """EnvFileProvider.is_available() always returns True, so it's always the fallback."""
        with patch.object(declaw_secrets_mod.KeychainProvider, "is_available", return_value=False), \
             patch.object(declaw_secrets_mod.VaultProvider, "is_available", return_value=False), \
             patch.object(declaw_secrets_mod.BitwardenProvider, "is_available", return_value=False), \
             patch.object(declaw_secrets_mod.OnePasswordProvider, "is_available", return_value=False):
            mgr = declaw_secrets_mod.SecretsManager.__new__(declaw_secrets_mod.SecretsManager)
            mgr.config = {}
            mgr.config_file = tmp_path / "config.json"
            result = mgr._auto_detect_provider()
            assert result == "env"


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------


class TestAuditLogging:
    """SecretsManager writes JSONL audit entries for every get/set operation."""

    @pytest.fixture
    def manager_with_env(self, declaw_secrets_mod, tmp_path):
        """Create a SecretsManager using env provider, all paths in tmp_path."""
        with patch.object(declaw_secrets_mod.KeychainProvider, "is_available", return_value=False), \
             patch.object(declaw_secrets_mod.VaultProvider, "is_available", return_value=False), \
             patch.object(declaw_secrets_mod.BitwardenProvider, "is_available", return_value=False), \
             patch.object(declaw_secrets_mod.OnePasswordProvider, "is_available", return_value=False):
            mgr = declaw_secrets_mod.SecretsManager(provider="env", audit=True)
            # Redirect file paths to tmp
            mgr.audit_file = tmp_path / "audit.log"
            mgr.provider.env_file = tmp_path / "secrets.env"
            return mgr

    def test_get_logs_access(self, manager_with_env):
        mgr = manager_with_env
        # Set then get so we have something to retrieve
        mgr.set("TEST_KEY", "test_val")
        mgr.get("TEST_KEY")

        lines = mgr.audit_file.read_text().strip().split("\n")
        # Should have at least 2 entries: one for set, one for get
        assert len(lines) >= 2

        get_entry = json.loads(lines[-1])
        assert get_entry["event_type"] == "secret_access"
        assert get_entry["action"] == "get"
        assert get_entry["key"] == "TEST_KEY"
        assert get_entry["success"] is True
        assert get_entry["provider"] == "env"

    def test_set_logs_access(self, manager_with_env):
        mgr = manager_with_env
        mgr.set("NEW_KEY", "new_val")

        lines = mgr.audit_file.read_text().strip().split("\n")
        set_entry = json.loads(lines[-1])
        assert set_entry["action"] == "set"
        assert set_entry["key"] == "NEW_KEY"
        assert set_entry["success"] is True

    def test_get_missing_key_logs_failure(self, manager_with_env):
        mgr = manager_with_env

        with pytest.raises(ValueError, match="Secret not found"):
            mgr.get("DOES_NOT_EXIST")

        lines = mgr.audit_file.read_text().strip().split("\n")
        fail_entry = json.loads(lines[-1])
        assert fail_entry["success"] is False
        assert fail_entry["key"] == "DOES_NOT_EXIST"

    def test_audit_entry_has_required_fields(self, manager_with_env):
        mgr = manager_with_env
        mgr.set("FIELD_CHECK", "val")

        entry = json.loads(mgr.audit_file.read_text().strip().split("\n")[-1])
        required = {"timestamp", "event_type", "action", "key", "success", "provider", "pid", "user"}
        assert required.issubset(entry.keys()), f"Missing fields: {required - entry.keys()}"

    def test_audit_timestamp_format(self, manager_with_env):
        """Timestamp should be ISO 8601 with UTC offset."""
        mgr = manager_with_env
        mgr.set("TS_KEY", "val")

        entry = json.loads(mgr.audit_file.read_text().strip().split("\n")[-1])
        # datetime.now(timezone.utc).isoformat() produces +00:00 suffix
        assert "+00:00" in entry["timestamp"]
        # Should parse as ISO datetime
        from datetime import datetime
        datetime.fromisoformat(entry["timestamp"])


# ---------------------------------------------------------------------------
# CLI argument parsing
# ---------------------------------------------------------------------------


class TestCLIParsing:
    """Test that the argparse setup produces correct Namespace objects."""

    def test_get_command(self, declaw_secrets_mod):
        """'get MY_KEY' should parse correctly."""
        parser = self._build_parser(declaw_secrets_mod)
        args = parser.parse_args(["get", "MY_KEY"])
        assert args.command == "get"
        assert args.key == "MY_KEY"
        assert args.provider is None  # default

    def test_set_command_with_value(self, declaw_secrets_mod):
        args = self._build_parser(declaw_secrets_mod).parse_args(["set", "KEY", "VALUE"])
        assert args.command == "set"
        assert args.key == "KEY"
        assert args.value == "VALUE"

    def test_set_command_without_value(self, declaw_secrets_mod):
        """set without explicit value should have value=None (prompts interactively)."""
        args = self._build_parser(declaw_secrets_mod).parse_args(["set", "KEY"])
        assert args.value is None

    def test_list_command(self, declaw_secrets_mod):
        args = self._build_parser(declaw_secrets_mod).parse_args(["list"])
        assert args.command == "list"

    def test_audit_command_with_key_filter(self, declaw_secrets_mod):
        args = self._build_parser(declaw_secrets_mod).parse_args(["audit", "--key", "SOME_KEY"])
        assert args.command == "audit"
        assert args.key == "SOME_KEY"

    def test_providers_command(self, declaw_secrets_mod):
        args = self._build_parser(declaw_secrets_mod).parse_args(["providers"])
        assert args.command == "providers"

    def test_explicit_provider_flag(self, declaw_secrets_mod):
        args = self._build_parser(declaw_secrets_mod).parse_args(["--provider", "vault", "get", "K"])
        assert args.provider == "vault"

    def test_invalid_provider_rejected(self, declaw_secrets_mod):
        with pytest.raises(SystemExit):
            self._build_parser(declaw_secrets_mod).parse_args(["--provider", "bogus", "get", "K"])

    def _build_parser(self, mod):
        """Reconstruct the argparse parser from main() logic.

        We re-create it here rather than calling main() to avoid side effects.
        """
        import argparse
        parser = argparse.ArgumentParser()
        parser.add_argument("--provider", choices=list(mod.SecretsManager.PROVIDERS.keys()), default=None)
        subparsers = parser.add_subparsers(dest="command", required=True)

        get_p = subparsers.add_parser("get")
        get_p.add_argument("key")

        set_p = subparsers.add_parser("set")
        set_p.add_argument("key")
        set_p.add_argument("value", nargs="?")

        subparsers.add_parser("list")

        audit_p = subparsers.add_parser("audit")
        audit_p.add_argument("--key")

        subparsers.add_parser("providers")

        return parser


# ---------------------------------------------------------------------------
# Provider is_available via mocked subprocess
# ---------------------------------------------------------------------------


class TestProviderAvailability:
    """Test is_available() for providers that shell out to CLI tools."""

    def test_vault_available_when_cli_exists(self, declaw_secrets_mod):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            provider = declaw_secrets_mod.VaultProvider({})
            assert provider.is_available() is True

    def test_vault_unavailable_when_cli_missing(self, declaw_secrets_mod):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            provider = declaw_secrets_mod.VaultProvider({})
            assert provider.is_available() is False

    def test_bitwarden_available_when_cli_exists(self, declaw_secrets_mod):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            provider = declaw_secrets_mod.BitwardenProvider()
            assert provider.is_available() is True

    def test_bitwarden_unavailable_when_cli_missing(self, declaw_secrets_mod):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            provider = declaw_secrets_mod.BitwardenProvider()
            assert provider.is_available() is False

    def test_onepassword_available_when_cli_exists(self, declaw_secrets_mod):
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            provider = declaw_secrets_mod.OnePasswordProvider({})
            assert provider.is_available() is True

    def test_onepassword_unavailable_when_cli_missing(self, declaw_secrets_mod):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            provider = declaw_secrets_mod.OnePasswordProvider({})
            assert provider.is_available() is False

    def test_keychain_available_on_darwin(self, declaw_secrets_mod):
        with patch("platform.system", return_value="Darwin"):
            provider = declaw_secrets_mod.KeychainProvider()
            assert provider.is_available() is True

    def test_keychain_unavailable_on_linux(self, declaw_secrets_mod):
        with patch("platform.system", return_value="Linux"):
            provider = declaw_secrets_mod.KeychainProvider()
            assert provider.is_available() is False


# ---------------------------------------------------------------------------
# Vault provider stdin piping (security fix: secret not on CLI)
# ---------------------------------------------------------------------------


class TestVaultSecretNotOnCLI:
    """VaultProvider.set() must pipe the secret via stdin, not as a CLI arg.

    Prior to this fix, the secret was passed as `value=SECRET` on the command
    line, making it visible to any local user via `ps aux` or /proc/cmdline.
    """

    def test_vault_set_passes_value_via_stdin(self, declaw_secrets_mod):
        """The 'value=-' arg tells vault to read from stdin, and input= pipes it."""
        provider = declaw_secrets_mod.VaultProvider({"vault": {
            "addr": "http://127.0.0.1:8200",
            "token": "test-token",
            "mount": "secret",
            "path": "declaw",
        }})
        provider.token = "test-token"

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            provider.set("MY_KEY", "super-secret-value")

            mock_run.assert_called_once()
            call_args = mock_run.call_args

            # The command list should contain "value=-", NOT "value=super-secret-value"
            cmd_list = call_args[0][0]
            assert "value=-" in cmd_list, "Secret should be read from stdin, not CLI arg"
            assert not any("super-secret-value" in str(arg) for arg in cmd_list), \
                "Secret value must NOT appear in command arguments"

            # The secret should be passed via input= kwarg
            assert call_args[1].get("input") == "super-secret-value", \
                "Secret must be piped via stdin (input= kwarg)"
            assert call_args[1].get("text") is True, \
                "text=True is required when passing string input"


# ---------------------------------------------------------------------------
# Keychain index-based list_keys (security fix: no dump-keychain)
# ---------------------------------------------------------------------------


class TestKeychainIndexBasedListing:
    """KeychainProvider.list_keys() must use a key index instead of
    dump-keychain, which would read the entire user keychain into memory."""

    @pytest.fixture
    def keychain_provider(self, declaw_secrets_mod, tmp_path):
        provider = declaw_secrets_mod.KeychainProvider()
        return provider

    def test_list_keys_returns_empty_when_no_index(self, keychain_provider, tmp_path):
        """Without an index file, list_keys returns empty list."""
        with patch.object(Path, "home", return_value=tmp_path):
            assert keychain_provider.list_keys() == []

    def test_list_keys_returns_verified_keys_from_index(self, keychain_provider, tmp_path):
        """Keys in the index that still exist in keychain are returned."""
        index_file = tmp_path / ".declaw" / "keychain-index.json"
        index_file.parent.mkdir(parents=True, exist_ok=True)
        index_file.write_text('["KEY_A", "KEY_B", "KEY_GONE"]')

        # Mock get() to say KEY_A and KEY_B exist, KEY_GONE doesn't
        def mock_get(key):
            return "value" if key in ("KEY_A", "KEY_B") else None

        with patch.object(Path, "home", return_value=tmp_path), \
             patch.object(keychain_provider, "get", side_effect=mock_get), \
             patch.object(keychain_provider, "_save_key_index"):
            result = keychain_provider.list_keys()
            assert "KEY_A" in result
            assert "KEY_B" in result
            assert "KEY_GONE" not in result

    def test_list_keys_does_not_call_dump_keychain(self, keychain_provider, tmp_path):
        """The old dump-keychain approach must NOT be used."""
        index_file = tmp_path / ".declaw" / "keychain-index.json"
        index_file.parent.mkdir(parents=True, exist_ok=True)
        index_file.write_text('["MY_KEY"]')

        with patch.object(Path, "home", return_value=tmp_path), \
             patch.object(keychain_provider, "get", return_value="val"), \
             patch("subprocess.run") as mock_run:
            keychain_provider.list_keys()
            # subprocess.run should NOT be called (no dump-keychain)
            mock_run.assert_not_called()

    def test_set_updates_key_index(self, declaw_secrets_mod, tmp_path):
        """After set(), the key should appear in the index file."""
        provider = declaw_secrets_mod.KeychainProvider()

        index_file = tmp_path / ".declaw" / "keychain-index.json"

        with patch.object(Path, "home", return_value=tmp_path), \
             patch.object(provider, "get", return_value=None), \
             patch("subprocess.run"):  # mock the actual keychain call
            provider._update_key_index("NEW_KEY")

        assert index_file.exists()
        keys = json.loads(index_file.read_text())
        assert "NEW_KEY" in keys

    def test_index_file_has_600_permissions(self, declaw_secrets_mod, tmp_path):
        """The keychain index must be owner-only (chmod 600)."""
        provider = declaw_secrets_mod.KeychainProvider()

        with patch.object(Path, "home", return_value=tmp_path):
            provider._save_key_index(["TEST_KEY"])

        index_file = tmp_path / ".declaw" / "keychain-index.json"
        mode = index_file.stat().st_mode
        assert stat.S_IMODE(mode) == 0o600


# ---------------------------------------------------------------------------
# SecretsManager._get_provider
# ---------------------------------------------------------------------------


class TestGetProvider:
    """SecretsManager._get_provider returns the correct class for each name."""

    def test_unknown_provider_raises(self, declaw_secrets_mod, tmp_path):
        mgr = declaw_secrets_mod.SecretsManager.__new__(declaw_secrets_mod.SecretsManager)
        mgr.config = {}
        with pytest.raises(ValueError, match="Unknown provider"):
            mgr._get_provider("nonexistent")

    def test_env_provider_returns_env_file_provider(self, declaw_secrets_mod, tmp_path):
        mgr = declaw_secrets_mod.SecretsManager.__new__(declaw_secrets_mod.SecretsManager)
        mgr.config = {}
        provider = mgr._get_provider("env")
        assert isinstance(provider, declaw_secrets_mod.EnvFileProvider)

    def test_keychain_provider_returns_keychain(self, declaw_secrets_mod, tmp_path):
        mgr = declaw_secrets_mod.SecretsManager.__new__(declaw_secrets_mod.SecretsManager)
        mgr.config = {}
        provider = mgr._get_provider("keychain")
        assert isinstance(provider, declaw_secrets_mod.KeychainProvider)
